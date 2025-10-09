use rpp_stark::hash::merkle::{
    compute_root_from_path, encode_leaf, Blake3MerkleTree, MerkleIndex, MerklePathElement,
    DIGEST_SIZE, LEAF_DOMAIN_TAG, NODE_DOMAIN_TAG,
};

fn hex_to_digest(hex: &str) -> [u8; DIGEST_SIZE] {
    let mut bytes = [0u8; DIGEST_SIZE];
    let decoded = hex::decode(hex).expect("valid hex digest");
    assert_eq!(decoded.len(), DIGEST_SIZE);
    bytes.copy_from_slice(&decoded);
    bytes
}

#[test]
fn stwo_leaf_and_node_domain_tags() {
    assert_eq!(LEAF_DOMAIN_TAG, 0x00);
    assert_eq!(NODE_DOMAIN_TAG, 0x01);
}

#[test]
fn stwo_single_leaf_root_matches_reference() {
    let leaves = [encode_leaf(b"stwo-leaf-0")];
    let tree = Blake3MerkleTree::from_leaves(leaves.iter()).expect("tree");
    assert_eq!(tree.leaf_count(), 1);
    let expected = hex_to_digest("af7424319f3641efc8170c036f932a42848183c651b027f6fc2f90c58c0c7b12");
    assert_eq!(tree.root(), expected);

    let path: Vec<MerklePathElement> = Vec::new();
    let computed = compute_root_from_path(&leaves[0], 0, 1, &path).expect("path");
    assert_eq!(computed, expected);
}

#[test]
fn stwo_two_leaf_path_matches_reference() {
    let leaves = [encode_leaf(b"stwo-leaf-0"), encode_leaf(b"stwo-leaf-1")];
    let tree = Blake3MerkleTree::from_leaves(leaves.iter()).expect("tree");
    assert_eq!(tree.leaf_count(), 2);
    let expected = hex_to_digest("27448c75832161aae392af81e24bddf5a0b58ab8bf58f345f78d4be1938ac29f");
    assert_eq!(tree.root(), expected);

    let sibling = hex_to_digest("af7424319f3641efc8170c036f932a42848183c651b027f6fc2f90c58c0c7b12");
    let path = [MerklePathElement {
        index: MerkleIndex(1),
        siblings: [sibling],
    }];
    let computed = compute_root_from_path(&leaves[1], 1, 2, &path).expect("path");
    assert_eq!(computed, expected);
}

#[test]
fn stwo_eight_leaf_path_matches_reference() {
    let leaves: Vec<_> = (0..8)
        .map(|i| encode_leaf(format!("stwo-leaf-{i}").as_bytes()))
        .collect();
    let tree = Blake3MerkleTree::from_leaves(leaves.iter()).expect("tree");
    assert_eq!(tree.leaf_count(), 8);
    let expected = hex_to_digest("710956d974d3ff4028491fcf5855a72a15783d6af3d17a2d34bce60ee5952cd6");
    assert_eq!(tree.root(), expected);

    let siblings = [
        hex_to_digest("035b5e356c0f95a99b4ae7204fabd99c8ae2770e6111d2a450f229f4e052f240"),
        hex_to_digest("d131f644cc0c7d9ea7200ff4be5e5e3f39c1b4b74d86bd132d07013370e00d76"),
        hex_to_digest("98bda2cee23b98983445a93d64803e8f8869258664da0539fb344ce78a1451f8"),
    ];
    let path = [
        MerklePathElement {
            index: MerkleIndex(1),
            siblings: [siblings[0]],
        },
        MerklePathElement {
            index: MerkleIndex(1),
            siblings: [siblings[1]],
        },
        MerklePathElement {
            index: MerkleIndex(1),
            siblings: [siblings[2]],
        },
    ];
    let computed = compute_root_from_path(&leaves[7], 7, 8, &path).expect("path");
    assert_eq!(computed, expected);
}
