use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Merkle inclusion proof for light client verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf hash being proven
    #[serde(with = "hex_bytes")]
    pub leaf: [u8; 32],
    /// Sibling hashes from leaf to root
    #[serde(with = "hex_bytes_vec")]
    pub siblings: Vec<[u8; 32]>,
    /// Index of the leaf in the tree
    pub index: usize,
    /// The merkle root
    #[serde(with = "hex_bytes")]
    pub root: [u8; 32],
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
        bytes.try_into().map_err(|_| serde::de::Error::custom("invalid length"))
    }
}

mod hex_bytes_vec {
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
                bytes.try_into().map_err(|_| serde::de::Error::custom("invalid length"))
            })
            .collect()
    }
}

/// Simple Merkle tree implementation for batching attestations
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl MerkleTree {
    /// Create a new merkle tree from a list of hashes
    pub fn new(mut leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            // Empty tree has a zero root
            return Self {
                leaves: vec![],
                root: [0u8; 32],
            };
        }

        // Build the tree bottom-up
        let root = Self::compute_root(&mut leaves);

        Self { leaves, root }
    }

    /// Get the merkle root
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get a merkle proof for a specific leaf index
    pub fn proof(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = index;
        let mut current_level = self.leaves.clone();

        while current_level.len() > 1 {
            // Get sibling
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                proof.push(current_level[sibling_index]);
            }

            // Move to next level
            current_level = Self::build_level(&current_level);
            current_index /= 2;
        }

        Some(proof)
    }

    /// Verify a merkle proof
    pub fn verify_proof(leaf: [u8; 32], proof: &[[u8; 32]], root: [u8; 32]) -> bool {
        let mut current = leaf;

        for sibling in proof {
            // Use sorted hash to be order-independent
            current = Self::hash_sorted(&current, sibling);
        }

        current == root
    }

    fn compute_root(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            current_level = Self::build_level(&current_level);
        }

        current_level[0]
    }

    fn build_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                Self::hash_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number of nodes - promote the last one
                chunk[0]
            };
            next_level.push(hash);
        }

        next_level
    }

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        Self::hash_sorted(left, right)
    }

    fn hash_sorted(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        // Sort to ensure deterministic hashing regardless of order
        let (left, right) = if a <= b { (a, b) } else { (b, a) };

        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(vec![]);
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_single_leaf() {
        let leaf = [1u8; 32];
        let tree = MerkleTree::new(vec![leaf]);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_multiple_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let tree = MerkleTree::new(leaves);

        // Root should be deterministic
        let root = tree.root();
        assert_ne!(root, [0u8; 32]);

        // Same leaves should produce same root
        let tree2 = MerkleTree::new(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
        assert_eq!(tree.root(), tree2.root());
    }

    #[test]
    fn test_proof_verification() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let tree = MerkleTree::new(leaves.clone());

        // Get proof for first leaf
        let proof = tree.proof(0).unwrap();
        assert!(MerkleTree::verify_proof(leaves[0], &proof, tree.root()));

        // Get proof for another leaf
        let proof = tree.proof(2).unwrap();
        assert!(MerkleTree::verify_proof(leaves[2], &proof, tree.root()));

        // Wrong leaf should fail
        assert!(!MerkleTree::verify_proof([99u8; 32], &proof, tree.root()));
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let tree = MerkleTree::new(leaves.clone());

        // Should still work
        for i in 0..leaves.len() {
            let proof = tree.proof(i).unwrap();
            assert!(MerkleTree::verify_proof(leaves[i], &proof, tree.root()));
        }
    }
}
