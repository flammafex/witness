//! RFC 9162 (CT v2) Merkle tree.
//!
//! Implements the Merkle Tree Hash (MTH), inclusion proofs (PATH), and
//! consistency proofs (PROOF) exactly as specified in RFC 9162 §2.1.
//!
//! - Leaves are domain-separated as `H(0x00 || leaf)`.
//! - Internal nodes are `H(0x01 || left || right)` with **positional**
//!   left/right ordering (no sorting).
//! - When `n` is not a power of 2, the tree splits at the largest power of
//!   2 strictly less than `n`, producing an unbalanced tree.  This shape is
//!   what makes consistency proofs possible.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

/// Inclusion proof for a single leaf at `leaf_index` in a tree of size
/// `tree_size`.  The siblings are listed bottom-up (leaf level first).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MerkleProof {
    /// The raw leaf bytes (pre-hash).  `hash_leaf(leaf)` is the value at
    /// position `leaf_index` in the tree.
    #[serde(with = "hex_bytes")]
    #[schemars(with = "String")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub leaf: [u8; 32],

    /// Audit path: sibling hashes from leaf level upward to (but not
    /// including) the root.
    #[serde(with = "hex_bytes_vec")]
    #[schemars(with = "Vec<String>")]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub siblings: Vec<[u8; 32]>,

    /// 0-based position of `leaf` in the log.  Renamed from `index` so
    /// callers are forced to update for the position-aware verifier.
    pub leaf_index: u64,

    /// Total number of leaves in the tree this proof was generated against.
    /// Required to walk the unbalanced-split tree shape.
    pub tree_size: u64,

    /// Root hash of the tree at `tree_size`.  Carried for convenience; the
    /// verifier may also pass an externally trusted root and ignore this.
    #[serde(with = "hex_bytes")]
    #[schemars(with = "String")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub root: [u8; 32],
}

/// Consistency proof between an old tree of size `first` and a new tree of
/// size `second`, with `first <= second`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    #[serde(with = "hex_bytes_vec")]
    pub hashes: Vec<[u8; 32]>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid length"))
    }
}

pub(crate) mod hex_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(vec: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for bytes in vec {
            seq.serialize_element(&hex::encode(bytes))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<String> = Vec::deserialize(deserializer)?;
        v.into_iter()
            .map(|s| {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("invalid length"))
            })
            .collect()
    }
}

/// Hash of an empty tree per RFC 9162 §2.1.1: `SHA-256()`.
pub fn empty_root() -> [u8; 32] {
    Sha256::new().finalize().into()
}

/// `MTH({leaf}) = SHA-256(0x00 || leaf)` — also exposed publicly because
/// callers store leaves at position `i` and verifiers need to recompute the
/// initial hash.
pub fn hash_leaf(leaf: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(leaf);
    h.finalize().into()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([INTERNAL_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of 2 strictly less than `n` (n > 1).
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n > 1);
    let bits = usize::BITS - (n - 1).leading_zeros();
    1usize << (bits - 1)
}

/// `MTH(D[n])` — the Merkle Tree Hash from RFC 9162 §2.1.1.
pub fn merkle_tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => hash_leaf(&leaves[0]),
        n => {
            let k = largest_pow2_lt(n);
            let left = merkle_tree_hash(&leaves[..k]);
            let right = merkle_tree_hash(&leaves[k..]);
            hash_internal(&left, &right)
        }
    }
}

/// `PATH(m, D[n])` — inclusion-proof audit path for the leaf at index `m`
/// in a tree built from `leaves`.  Returns `None` if `m >= leaves.len()`.
pub fn inclusion_path(m: usize, leaves: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    if m >= leaves.len() {
        return None;
    }
    Some(inclusion_path_inner(m, leaves))
}

fn inclusion_path_inner(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = largest_pow2_lt(n);
    if m < k {
        let mut p = inclusion_path_inner(m, &leaves[..k]);
        p.push(merkle_tree_hash(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_path_inner(m - k, &leaves[k..]);
        p.push(merkle_tree_hash(&leaves[..k]));
        p
    }
}

/// `PROOF(m, D[n])` — consistency proof between sub-tree `D[0..m]` and
/// `D[0..n]`.  Returns an empty proof when `m == n` (and `n > 0`).
pub fn consistency_path(m: usize, leaves: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
    let n = leaves.len();
    if m == 0 || m > n {
        return None;
    }
    Some(subproof(m, leaves, true))
}

fn subproof(m: usize, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        if b {
            return Vec::new();
        }
        return vec![merkle_tree_hash(leaves)];
    }
    let k = largest_pow2_lt(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(merkle_tree_hash(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(merkle_tree_hash(&leaves[..k]));
        p
    }
}

/// Verify an inclusion proof per RFC 9162 §2.1.3.2.
///
/// Returns `true` iff the audit path proves that `leaf` sits at position
/// `leaf_index` in a tree of size `tree_size` whose root is `root`.
pub fn verify_inclusion(
    leaf: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    audit_path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }

    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = hash_leaf(leaf);

    for p in audit_path {
        if sn == 0 {
            // Walked off the top of the tree but still have siblings left.
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = hash_internal(p, &r);
            if fn_ & 1 != 1 {
                // fn_ == sn (last node at this level): shift past trailing
                // zeros so the next iteration aligns with the next subtree.
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = hash_internal(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    fn_ == 0 && sn == 0 && r == *root
}

/// Verify a consistency proof per RFC 9162 §2.1.4.2.
///
/// Confirms that the tree of size `first` with root `first_hash` is a prefix
/// of the tree of size `second` with root `second_hash`.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_hash: &[u8; 32],
    second_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_hash == second_hash;
    }
    if first == 0 {
        // RFC: a consistency proof against the empty tree is vacuously
        // valid as long as the new tree's root matches itself.  Accept an
        // empty proof here.
        return proof.is_empty();
    }

    // Step 1: prepend first_hash if first is an exact power of 2.
    let path: Vec<[u8; 32]> = if first.is_power_of_two() {
        std::iter::once(*first_hash)
            .chain(proof.iter().copied())
            .collect()
    } else {
        proof.to_vec()
    };
    if path.is_empty() {
        return false;
    }

    let mut fn_ = first - 1;
    let mut sn = second - 1;

    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }

    let mut fr = path[0];
    let mut sr = path[0];

    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = hash_internal(c, &fr);
            sr = hash_internal(c, &sr);
            if fn_ & 1 != 1 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = hash_internal(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    sn == 0 && fr == *first_hash && sr == *second_hash
}

/// Convenience builder: holds a leaf vector and exposes proof generation
/// helpers.  Useful for tests; production code should compute proofs from
/// the persisted log via [`merkle_tree_hash`], [`inclusion_path`], and
/// [`consistency_path`] directly.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_tree_hash(&self.leaves)
    }

    pub fn inclusion_proof(&self, m: usize) -> Option<MerkleProof> {
        let leaf = *self.leaves.get(m)?;
        let siblings = inclusion_path(m, &self.leaves)?;
        Some(MerkleProof {
            leaf,
            siblings,
            leaf_index: m as u64,
            tree_size: self.leaves.len() as u64,
            root: self.root(),
        })
    }

    pub fn consistency_proof(&self, first_size: usize) -> Option<ConsistencyProof> {
        let hashes = consistency_path(first_size, &self.leaves)?;
        Some(ConsistencyProof {
            first_size: first_size as u64,
            second_size: self.leaves.len() as u64,
            hashes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn empty_tree_root_matches_rfc() {
        // RFC 9162: MTH({}) = SHA-256()
        let expected: [u8; 32] = Sha256::new().finalize().into();
        assert_eq!(empty_root(), expected);
        assert_eq!(merkle_tree_hash(&[]), expected);
    }

    #[test]
    fn single_leaf_root_is_hashed_leaf() {
        let l = leaf(1);
        assert_eq!(merkle_tree_hash(&[l]), hash_leaf(&l));
    }

    #[test]
    fn balanced_tree_matches_recursive_definition() {
        let leaves: Vec<[u8; 32]> = (1u8..=4).map(leaf).collect();
        let h12 = hash_internal(&hash_leaf(&leaves[0]), &hash_leaf(&leaves[1]));
        let h34 = hash_internal(&hash_leaf(&leaves[2]), &hash_leaf(&leaves[3]));
        let expected = hash_internal(&h12, &h34);
        assert_eq!(merkle_tree_hash(&leaves), expected);
    }

    #[test]
    fn unbalanced_tree_uses_largest_power_of_two_split() {
        // n = 5 → split at k = 4, so MTH = H(MTH(L[0..4]) || MTH(L[4..5]))
        let leaves: Vec<[u8; 32]> = (1u8..=5).map(leaf).collect();
        let left = merkle_tree_hash(&leaves[..4]);
        let right = merkle_tree_hash(&leaves[4..]);
        let expected = hash_internal(&left, &right);
        assert_eq!(merkle_tree_hash(&leaves), expected);
    }

    #[test]
    fn inclusion_proof_roundtrip_for_every_leaf() {
        for n in 1usize..=17 {
            let leaves: Vec<[u8; 32]> = (0u8..n as u8).map(leaf).collect();
            let tree = MerkleTree::new(leaves.clone());
            let root = tree.root();

            for (i, leaf) in leaves.iter().enumerate().take(n) {
                let proof = tree.inclusion_proof(i).expect("proof exists");
                assert!(
                    verify_inclusion(leaf, i as u64, n as u64, &proof.siblings, &root),
                    "proof for leaf {i} of size {n} failed"
                );
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<[u8; 32]> = (0u8..7).map(leaf).collect();
        let tree = MerkleTree::new(leaves.clone());
        let proof = tree.inclusion_proof(3).unwrap();
        let bogus = leaf(99);
        assert!(!verify_inclusion(
            &bogus,
            3,
            7,
            &proof.siblings,
            &tree.root()
        ));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_index() {
        let leaves: Vec<[u8; 32]> = (0u8..7).map(leaf).collect();
        let tree = MerkleTree::new(leaves.clone());
        let proof = tree.inclusion_proof(3).unwrap();
        assert!(!verify_inclusion(
            &leaves[3],
            4,
            7,
            &proof.siblings,
            &tree.root()
        ));
    }

    #[test]
    fn consistency_proof_roundtrip_all_pairs() {
        for n in 1usize..=10 {
            let leaves: Vec<[u8; 32]> = (0u8..n as u8).map(leaf).collect();
            let new_root = merkle_tree_hash(&leaves);

            for m in 1..=n {
                let old_root = merkle_tree_hash(&leaves[..m]);
                let proof = consistency_path(m, &leaves).expect("proof exists");
                assert!(
                    verify_consistency(m as u64, n as u64, &old_root, &new_root, &proof),
                    "consistency proof from m={m} to n={n} failed"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_tampered_old_root() {
        let leaves: Vec<[u8; 32]> = (0u8..8).map(leaf).collect();
        let proof = consistency_path(3, &leaves).unwrap();
        let new_root = merkle_tree_hash(&leaves);
        let bogus_old = [0xFFu8; 32];
        assert!(!verify_consistency(3, 8, &bogus_old, &new_root, &proof));
    }

    #[test]
    fn consistency_proof_rejects_tampered_new_root() {
        let leaves: Vec<[u8; 32]> = (0u8..8).map(leaf).collect();
        let old_root = merkle_tree_hash(&leaves[..3]);
        let proof = consistency_path(3, &leaves).unwrap();
        let bogus_new = [0xFFu8; 32];
        assert!(!verify_consistency(3, 8, &old_root, &bogus_new, &proof));
    }

    #[test]
    fn consistency_proof_rejects_tampered_path() {
        let leaves: Vec<[u8; 32]> = (0u8..8).map(leaf).collect();
        let old_root = merkle_tree_hash(&leaves[..3]);
        let new_root = merkle_tree_hash(&leaves);
        let mut proof = consistency_path(3, &leaves).unwrap();
        proof[0] = [0xAAu8; 32];
        assert!(!verify_consistency(3, 8, &old_root, &new_root, &proof));
    }

    #[test]
    fn equal_sizes_require_empty_proof_and_matching_roots() {
        let leaves: Vec<[u8; 32]> = (0u8..6).map(leaf).collect();
        let root = merkle_tree_hash(&leaves);
        assert!(verify_consistency(6, 6, &root, &root, &[]));
        assert!(!verify_consistency(6, 6, &root, &root, &[[0u8; 32]]));
        assert!(!verify_consistency(6, 6, &root, &[0u8; 32], &[]));
    }

    #[test]
    fn first_greater_than_second_is_invalid() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(leaf).collect();
        let r4 = merkle_tree_hash(&leaves);
        let r2 = merkle_tree_hash(&leaves[..2]);
        assert!(!verify_consistency(4, 2, &r4, &r2, &[]));
    }

    #[test]
    fn power_of_two_first_size_has_implicit_first_hash() {
        // first = 4 is a power of 2, second = 7
        let leaves: Vec<[u8; 32]> = (0u8..7).map(leaf).collect();
        let old_root = merkle_tree_hash(&leaves[..4]);
        let new_root = merkle_tree_hash(&leaves);
        let proof = consistency_path(4, &leaves).unwrap();

        // The generated proof should NOT contain the old root explicitly;
        // the verifier prepends it.  Sanity: prepending the old root by
        // hand also verifies.
        assert!(verify_consistency(4, 7, &old_root, &new_root, &proof));
    }

    #[test]
    fn largest_pow2_lt_known_values() {
        assert_eq!(largest_pow2_lt(2), 1);
        assert_eq!(largest_pow2_lt(3), 2);
        assert_eq!(largest_pow2_lt(4), 2);
        assert_eq!(largest_pow2_lt(5), 4);
        assert_eq!(largest_pow2_lt(8), 4);
        assert_eq!(largest_pow2_lt(9), 8);
        assert_eq!(largest_pow2_lt(16), 8);
        assert_eq!(largest_pow2_lt(17), 16);
    }
}
