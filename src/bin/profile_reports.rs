use std::env;
use std::fs;
use std::path::PathBuf;

use rpp_stark::config::{
    compute_param_digest, CommonIdentifiers, ProfileConfig, ProfileId, ProofKind,
    COMMON_IDENTIFIERS, PROFILE_HIGH_SECURITY_CONFIG, PROFILE_HISEC, PROFILE_STANDARD_CONFIG,
    PROFILE_STD, PROFILE_THROUGHPUT_CONFIG,
};
use rpp_stark::field::FieldElement;
use rpp_stark::fri::types::{FriProof, FriSecurityLevel};
use rpp_stark::hash::{hash, Hasher, OutputReader};
use rpp_stark::proof::envelope::{
    compute_commitment_digest, compute_integrity_digest, serialize_public_inputs,
    FriParametersMirror, OutOfDomainOpening, ProofEnvelope, ProofEnvelopeBody, ProofEnvelopeHeader,
    PROOF_VERSION,
};
use rpp_stark::proof::public_inputs::{ExecutionHeaderV1, PublicInputVersion, PublicInputs};
use rpp_stark::utils::serialization::DigestBytes;

#[derive(Clone)]
struct ProfileDescriptor {
    code: &'static str,
    profile: ProfileConfig,
}

#[derive(Clone)]
struct ProfileReport {
    descriptor: ProfileDescriptor,
    param_digest_hex: String,
    run_a_hash: String,
    run_b_hash: String,
    proof_size: usize,
    max_proof_size: u32,
}

fn main() {
    let mut args = env::args().skip(1);
    let mut output_dir = PathBuf::from("reports");
    let mut include_throughput = env::var("ENABLE_PROFILE_THR")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                if let Some(value) = args.next() {
                    output_dir = PathBuf::from(value);
                }
            }
            "--include-throughput" => include_throughput = true,
            _ => {}
        }
    }

    let mut descriptors = vec![
        ProfileDescriptor {
            code: "PROFILE_STD",
            profile: PROFILE_STANDARD_CONFIG.clone(),
        },
        ProfileDescriptor {
            code: "PROFILE_HISEC",
            profile: PROFILE_HIGH_SECURITY_CONFIG.clone(),
        },
    ];

    if include_throughput {
        descriptors.push(ProfileDescriptor {
            code: "PROFILE_THR",
            profile: PROFILE_THROUGHPUT_CONFIG.clone(),
        });
    }

    let reports: Vec<ProfileReport> = descriptors
        .into_iter()
        .map(|descriptor| build_report(descriptor, &COMMON_IDENTIFIERS))
        .collect();

    fs::create_dir_all(&output_dir)
        .unwrap_or_else(|err| panic!("failed to create report directory {output_dir:?}: {err}"));

    write_file(
        &output_dir.join("PARAMS_REPORT.md"),
        &render_params_report(&reports),
    );
    write_file(
        &output_dir.join("DETERMINISM_REPORT.md"),
        &render_determinism_report(&reports),
    );
    write_file(
        &output_dir.join("SIZE_REPORT.md"),
        &render_size_report(&reports),
    );
}

fn build_report(descriptor: ProfileDescriptor, common: &CommonIdentifiers) -> ProfileReport {
    let profile = descriptor.profile.clone();
    let param_digest = compute_param_digest(&profile, common);
    let param_digest_hex = hex_string(&param_digest.0.bytes);

    let (run_a_hash, proof_size) = sample_hash(&profile, &param_digest, "duplicate-run");
    let (run_b_hash, _) = sample_hash(&profile, &param_digest, "duplicate-run");

    ProfileReport {
        descriptor,
        param_digest_hex,
        run_a_hash,
        run_b_hash,
        proof_size,
        max_proof_size: profile.limits.max_proof_size_bytes,
    }
}

fn sample_hash(
    profile: &ProfileConfig,
    param_digest: &rpp_stark::config::ParamDigest,
    run_label: &str,
) -> (String, usize) {
    let envelope = build_sample_envelope(profile, param_digest, run_label);
    let bytes = envelope.to_bytes();
    let digest = hash(&bytes);
    (format!("{}", digest.to_hex()), bytes.len())
}

fn build_sample_envelope(
    profile: &ProfileConfig,
    param_digest: &rpp_stark::config::ParamDigest,
    run_label: &str,
) -> ProofEnvelope {
    let mut reader = sample_reader(profile.id, run_label);

    let mut core_root = [0u8; 32];
    reader.fill(&mut core_root);
    let mut aux_root = [0u8; 32];
    reader.fill(&mut aux_root);

    let mut fri_layer_roots = Vec::new();
    for _ in 0..2 {
        fri_layer_roots.push(sample_digest(&mut reader));
    }

    let ood_openings = vec![OutOfDomainOpening {
        point: sample_digest(&mut reader),
        core_values: vec![sample_digest(&mut reader)],
        aux_values: vec![],
        composition_value: sample_digest(&mut reader),
    }];

    let final_polynomial: Vec<FieldElement> = (0..4)
        .map(|_| FieldElement::from(sample_u64(&mut reader)))
        .collect();

    let fri_proof = FriProof {
        security_level: profile_to_security_level(profile.id),
        initial_domain_size: 16,
        layer_roots: fri_layer_roots.clone(),
        final_polynomial,
        final_polynomial_digest: sample_digest(&mut reader),
        queries: Vec::new(),
    };

    let mut body = ProofEnvelopeBody {
        core_root,
        aux_root,
        fri_layer_roots: fri_layer_roots.clone(),
        ood_openings,
        fri_proof,
        fri_parameters: FriParametersMirror {
            fold: 2,
            cap_degree: profile.limits.max_layers as u16,
            cap_size: profile.limits.max_queries as u32,
            query_budget: profile.fri_queries,
        },
        integrity_digest: DigestBytes { bytes: [0u8; 32] },
    };

    let commitment_digest =
        compute_commitment_digest(&body.core_root, &body.aux_root, &body.fri_layer_roots);
    let public_inputs = sample_public_inputs(profile, run_label);
    let payload = encode_body(&body);
    let body_length = (payload.len() + 32) as u32;
    let header_length = (2 + 32 + 32 + 4 + public_inputs.len() + 32 + 4 + 4) as u32;

    let header = ProofEnvelopeHeader {
        proof_version: PROOF_VERSION,
        proof_kind: ProofKind::Tx,
        param_digest: param_digest.clone(),
        air_spec_id: profile.air_spec_ids.get(ProofKind::Tx).clone(),
        public_inputs,
        commitment_digest: DigestBytes {
            bytes: commitment_digest,
        },
        header_length,
        body_length,
    };

    let header_bytes = encode_header(&header, &payload);
    let integrity = compute_integrity_digest(&header_bytes, &payload);
    body.integrity_digest = DigestBytes { bytes: integrity };

    ProofEnvelope { header, body }
}

fn sample_public_inputs(profile: &ProfileConfig, run_label: &str) -> Vec<u8> {
    let header = ExecutionHeaderV1 {
        version: PublicInputVersion::V1,
        program_digest: DigestBytes {
            bytes: sample_digest_from_label(profile, run_label, b"program"),
        },
        trace_length: profile.limits.per_proof_max_trace_steps.tx,
        trace_width: profile.limits.per_proof_max_trace_width.tx as u32,
    };
    let body = format!(
        "profile={}\nrun={}\nproof_version={}",
        profile.name, run_label, PROOF_VERSION
    );
    let inputs = PublicInputs::Execution {
        header,
        body: body.as_bytes(),
    };
    serialize_public_inputs(&inputs)
}

fn sample_reader(profile_id: ProfileId, run_label: &str) -> OutputReader {
    let mut hasher = Hasher::new();
    hasher.update(b"rpp-stark/sample-envelope");
    hasher.update(&profile_id.to_le_bytes());
    hasher.update(run_label.as_bytes());
    hasher.finalize_xof()
}

fn sample_digest(reader: &mut OutputReader) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    reader.fill(&mut bytes);
    bytes
}

fn sample_u64(reader: &mut OutputReader) -> u64 {
    let mut bytes = [0u8; 8];
    reader.fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

fn sample_digest_from_label(profile: &ProfileConfig, run_label: &str, scope: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(profile.name.as_bytes());
    hasher.update(&profile.id.to_le_bytes());
    hasher.update(run_label.as_bytes());
    hasher.update(scope);
    hasher.finalize().into_bytes()
}

fn profile_to_security_level(id: ProfileId) -> FriSecurityLevel {
    if id == PROFILE_STD {
        FriSecurityLevel::Standard
    } else if id == PROFILE_HISEC {
        FriSecurityLevel::HiSec
    } else {
        FriSecurityLevel::Throughput
    }
}

fn render_params_report(reports: &[ProfileReport]) -> String {
    let mut rows = String::new();
    for report in reports {
        let profile = &report.descriptor.profile;
        rows.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            report.descriptor.code,
            profile.id.0,
            profile.name,
            profile.security_goal,
            profile.fri_queries,
            report.param_digest_hex
        ));
    }

    format!(
        "# Parameter Report\n\
\nProfiles are listed in canonical order. The digest column records the deterministic\nparameter hash bound to `COMMON_IDENTIFIERS`.\n\
\n| Profile | ID | Name | Security goal | FRI queries | Param digest |\n| --- | --- | --- | --- | --- | --- |\n{}",
        rows
    )
}

fn render_determinism_report(reports: &[ProfileReport]) -> String {
    let mut rows = String::new();
    for report in reports {
        let status = if report.run_a_hash == report.run_b_hash {
            "match"
        } else {
            "mismatch"
        };
        rows.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            report.descriptor.code, report.run_a_hash, report.run_b_hash, status
        ));
    }

    format!(
        "# Determinism Report\n\
\nEach profile is executed twice with identical inputs. Matching hashes demonstrate\nthat byte outputs are reproducible.\n\
\n| Profile | Run A hash | Run B hash | Status |\n| --- | --- | --- | --- |\n{}",
        rows
    )
}

fn render_size_report(reports: &[ProfileReport]) -> String {
    let mut rows = String::new();
    for report in reports {
        let headroom = report
            .max_proof_size
            .saturating_sub(report.proof_size as u32);
        rows.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            report.descriptor.code, report.proof_size, report.max_proof_size, headroom
        ));
    }

    format!(
        "# Size Report\n\
\nThe synthetic envelope size is compared against the documented profile limit.\n\
\n| Profile | Sample proof bytes | Max proof size (bytes) | Headroom |\n| --- | --- | --- | --- |\n{}",
        rows
    )
}

fn encode_header(header: &ProofEnvelopeHeader, body_payload: &[u8]) -> Vec<u8> {
    debug_assert_eq!(
        header.body_length as usize,
        body_payload.len() + 32,
        "body length must include integrity digest"
    );
    let expected_header_length = 2 + 32 + 32 + 4 + header.public_inputs.len() + 32 + 4 + 4;
    debug_assert_eq!(
        header.header_length as usize, expected_header_length,
        "header length must match canonical layout"
    );

    let mut buffer = Vec::with_capacity(header.header_length as usize);
    buffer.push(header.proof_version);
    buffer.push(encode_proof_kind(header.proof_kind));
    buffer.extend_from_slice(&header.param_digest.0.bytes);
    buffer.extend_from_slice(header.air_spec_id.as_bytes());
    buffer.extend_from_slice(&(header.public_inputs.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&header.public_inputs);
    buffer.extend_from_slice(&header.commitment_digest.bytes);
    buffer.extend_from_slice(&header.header_length.to_le_bytes());
    buffer.extend_from_slice(&header.body_length.to_le_bytes());
    buffer
}

fn encode_body(body: &ProofEnvelopeBody) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&body.core_root);
    buffer.extend_from_slice(&body.aux_root);
    buffer.extend_from_slice(&(body.fri_layer_roots.len() as u32).to_le_bytes());
    for root in &body.fri_layer_roots {
        buffer.extend_from_slice(root);
    }

    buffer.extend_from_slice(&(body.ood_openings.len() as u32).to_le_bytes());
    for opening in &body.ood_openings {
        let encoded = encode_out_of_domain(opening);
        buffer.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&encoded);
    }

    let fri_bytes = encode_fri_proof(&body.fri_proof);
    buffer.extend_from_slice(&(fri_bytes.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&fri_bytes);

    buffer.push(body.fri_parameters.fold);
    buffer.extend_from_slice(&body.fri_parameters.cap_degree.to_le_bytes());
    buffer.extend_from_slice(&body.fri_parameters.cap_size.to_le_bytes());
    buffer.extend_from_slice(&body.fri_parameters.query_budget.to_le_bytes());
    buffer
}

fn encode_out_of_domain(opening: &OutOfDomainOpening) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&opening.point);
    buffer.extend_from_slice(&(opening.core_values.len() as u32).to_le_bytes());
    for value in &opening.core_values {
        buffer.extend_from_slice(value);
    }
    buffer.extend_from_slice(&(opening.aux_values.len() as u32).to_le_bytes());
    for value in &opening.aux_values {
        buffer.extend_from_slice(value);
    }
    buffer.extend_from_slice(&opening.composition_value);
    buffer
}

fn encode_fri_proof(proof: &FriProof) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.push(match proof.security_level {
        FriSecurityLevel::Standard => 0,
        FriSecurityLevel::HiSec => 1,
        FriSecurityLevel::Throughput => 2,
    });
    buffer.extend_from_slice(&(proof.initial_domain_size as u32).to_le_bytes());
    buffer.extend_from_slice(&(proof.layer_roots.len() as u32).to_le_bytes());
    for root in &proof.layer_roots {
        buffer.extend_from_slice(root);
    }
    buffer.extend_from_slice(&(proof.final_polynomial.len() as u32).to_le_bytes());
    for value in &proof.final_polynomial {
        buffer.extend_from_slice(&field_element_to_bytes(*value));
    }
    buffer.extend_from_slice(&proof.final_polynomial_digest);
    buffer.extend_from_slice(&(proof.queries.len() as u32).to_le_bytes());
    for query in &proof.queries {
        buffer.extend_from_slice(&(query.position as u64).to_le_bytes());
        buffer.extend_from_slice(&(query.layers.len() as u32).to_le_bytes());
        for layer in &query.layers {
            buffer.extend_from_slice(&field_element_to_bytes(layer.value));
            buffer.extend_from_slice(&(layer.path.len() as u32).to_le_bytes());
            for element in &layer.path {
                buffer.push(element.index.0);
                for sibling in &element.siblings {
                    buffer.extend_from_slice(sibling);
                }
            }
        }
        buffer.extend_from_slice(&field_element_to_bytes(query.final_value));
    }
    buffer
}

fn encode_proof_kind(kind: ProofKind) -> u8 {
    match kind {
        ProofKind::Tx => 0,
        ProofKind::State => 1,
        ProofKind::Pruning => 2,
        ProofKind::Uptime => 3,
        ProofKind::Consensus => 4,
        ProofKind::Identity => 5,
        ProofKind::Aggregation => 6,
        ProofKind::VRF => 7,
    }
}

fn field_element_to_bytes(value: FieldElement) -> [u8; 8] {
    let canonical: u64 = value.into();
    canonical.to_le_bytes()
}

fn write_file(path: &PathBuf, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|err| {
        panic!("failed to write {}: {err}", path.display());
    });
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}
