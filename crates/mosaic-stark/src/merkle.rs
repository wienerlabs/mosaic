//! Merkle authentication path verification (SHA-256).
//!
//! Both Winterfell and Plonky3 use SHA-256 (or BLAKE3) Merkle trees
//! for trace and FRI-layer commitments. This module implements the
//! path-check primitive: given a leaf, path of sibling digests, and a
//! leaf index, recompute the root and compare to a claimed root.
//!
//! ## Index → direction bit
//!
//! At layer `d` (depth from leaf), bit `d` of `index` determines
//! whether our node is the **left** child (bit = 0, sibling is the
//! right node) or **right** child (bit = 1, sibling is the left
//! node). The hash concatenation order depends on this bit.

use crate::canonical::sizes::DIGEST_LEN;
use alloc::vec::Vec;
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// Verify a SHA-256 Merkle authentication path.
///
/// - `leaf` — 32-byte digest at position `leaf_index` in the tree.
/// - `path` — `tree_depth` sibling digests, ordered leaf-to-root.
/// - `leaf_index` — 0-based position; bit k of index selects our
///   child position at layer k.
/// - `expected_root` — root to compare against.
///
/// Returns `Ok(())` if the recomputed root equals `expected_root`,
/// otherwise `OnChainError::VerificationFailed`.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if `leaf.len() != 32` or
///   `path.len()` is not a multiple of 32.
/// - [`OnChainError::VerificationFailed`] on root mismatch.
/// - [`OnChainError::Sha256SyscallFailed`] on hash failure.
pub fn verify_path<B: SyscallBackend + ?Sized>(
    backend: &B,
    leaf: &[u8],
    path: &[u8],
    leaf_index: u64,
    expected_root: &[u8],
) -> Result<(), OnChainError> {
    if leaf.len() != DIGEST_LEN || expected_root.len() != DIGEST_LEN {
        return Err(OnChainError::ProofLengthMismatch);
    }
    if !path.len().is_multiple_of(DIGEST_LEN) {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let depth = path.len() / DIGEST_LEN;

    let mut current = [0u8; DIGEST_LEN];
    current.copy_from_slice(leaf);
    let mut index = leaf_index;

    for d in 0..depth {
        let sibling = &path[d * DIGEST_LEN..(d + 1) * DIGEST_LEN];
        // Bit d of the original index determines child position at this layer.
        let we_are_right = (index & 1) == 1;
        let hash = if we_are_right {
            // Sibling is left; we are right → hash(sibling ‖ current).
            backend.sha256(&[sibling, &current])?
        } else {
            // We are left; sibling is right → hash(current ‖ sibling).
            backend.sha256(&[&current, sibling])?
        };
        current = hash;
        index >>= 1;
    }

    if &current != expected_root {
        return Err(OnChainError::VerificationFailed);
    }
    Ok(())
}

/// Construct a Merkle root from an array of 32-byte leaves by binary
/// hashing. Used in tests as the oracle that the path verifier checks
/// against.
///
/// Only available in tests since it allocates O(n) digests; on-chain
/// code only does path-check, not full-tree construction.
#[cfg(test)]
pub fn construct_root<B: SyscallBackend + ?Sized>(
    backend: &B,
    leaves: &[[u8; DIGEST_LEN]],
) -> Result<[u8; DIGEST_LEN], OnChainError> {
    if leaves.is_empty() {
        return Err(OnChainError::ProofLengthMismatch);
    }
    if leaves.len() == 1 {
        return Ok(leaves[0]);
    }
    if !leaves.len().is_power_of_two() {
        return Err(OnChainError::ProofLengthMismatch);
    }

    let mut level: Vec<[u8; DIGEST_LEN]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<[u8; DIGEST_LEN]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let h = backend.sha256(&[&pair[0], &pair[1]])?;
            next.push(h);
        }
        level = next;
    }
    Ok(level[0])
}

/// Construct an authentication path for a leaf at `leaf_index` — used
/// in tests to generate inputs for `verify_path`.
#[cfg(test)]
pub fn construct_path<B: SyscallBackend + ?Sized>(
    backend: &B,
    leaves: &[[u8; DIGEST_LEN]],
    leaf_index: usize,
) -> Result<Vec<u8>, OnChainError> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let mut path: Vec<u8> = Vec::new();
    let mut level: Vec<[u8; DIGEST_LEN]> = leaves.to_vec();
    let mut idx = leaf_index;

    while level.len() > 1 {
        let sibling_idx = idx ^ 1;
        path.extend_from_slice(&level[sibling_idx]);
        let mut next: Vec<[u8; DIGEST_LEN]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let h = backend.sha256(&[&pair[0], &pair[1]])?;
            next.push(h);
        }
        level = next;
        idx >>= 1;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mosaic_core::syscall::host::HostBackend;

    #[test]
    fn verify_path_accepts_valid() {
        let backend = HostBackend::new();
        // 4 leaves → depth 2 tree.
        let leaves: [[u8; DIGEST_LEN]; 4] = [
            [0x11; DIGEST_LEN],
            [0x22; DIGEST_LEN],
            [0x33; DIGEST_LEN],
            [0x44; DIGEST_LEN],
        ];
        let root = construct_root(&backend, &leaves).unwrap();

        for idx in 0..4 {
            let path = construct_path(&backend, &leaves, idx).unwrap();
            let r = verify_path(&backend, &leaves[idx], &path, idx as u64, &root);
            assert!(r.is_ok(), "path verification failed at idx={idx}: {r:?}");
        }
    }

    #[test]
    fn verify_path_accepts_8_leaves() {
        let backend = HostBackend::new();
        let leaves: alloc::vec::Vec<[u8; DIGEST_LEN]> =
            (0..8).map(|i| [i as u8; DIGEST_LEN]).collect();
        let root = construct_root(&backend, &leaves).unwrap();
        for idx in 0..8 {
            let path = construct_path(&backend, &leaves, idx).unwrap();
            assert!(verify_path(&backend, &leaves[idx], &path, idx as u64, &root).is_ok());
        }
    }

    #[test]
    fn verify_path_rejects_wrong_root() {
        let backend = HostBackend::new();
        let leaves: [[u8; DIGEST_LEN]; 4] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
        let path = construct_path(&backend, &leaves, 0).unwrap();
        let wrong_root = [0xFF; DIGEST_LEN];
        assert!(matches!(
            verify_path(&backend, &leaves[0], &path, 0, &wrong_root),
            Err(OnChainError::VerificationFailed),
        ));
    }

    #[test]
    fn verify_path_rejects_wrong_index() {
        let backend = HostBackend::new();
        let leaves: [[u8; DIGEST_LEN]; 4] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
        let root = construct_root(&backend, &leaves).unwrap();
        // Path for leaf 0, but claim index 1.
        let path = construct_path(&backend, &leaves, 0).unwrap();
        assert!(matches!(
            verify_path(&backend, &leaves[0], &path, 1, &root),
            Err(OnChainError::VerificationFailed),
        ));
    }

    #[test]
    fn verify_path_rejects_tampered_path() {
        let backend = HostBackend::new();
        let leaves: [[u8; DIGEST_LEN]; 4] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
        let root = construct_root(&backend, &leaves).unwrap();
        let mut path = construct_path(&backend, &leaves, 0).unwrap();
        // Flip a bit in the first sibling.
        path[0] ^= 0x01;
        assert!(matches!(
            verify_path(&backend, &leaves[0], &path, 0, &root),
            Err(OnChainError::VerificationFailed),
        ));
    }

    #[test]
    fn verify_path_rejects_wrong_leaf_length() {
        let backend = HostBackend::new();
        let short_leaf = [0u8; 31];
        let root = [0u8; DIGEST_LEN];
        let path = [0u8; DIGEST_LEN];
        assert!(matches!(
            verify_path(&backend, &short_leaf, &path, 0, &root),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn verify_path_rejects_path_not_multiple_of_digest() {
        let backend = HostBackend::new();
        let leaf = [0u8; DIGEST_LEN];
        let root = [0u8; DIGEST_LEN];
        let bad_path = [0u8; DIGEST_LEN + 5];
        assert!(matches!(
            verify_path(&backend, &leaf, &bad_path, 0, &root),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn verify_path_single_leaf_tree() {
        // Depth 0 tree — path is empty, root == leaf.
        let backend = HostBackend::new();
        let leaf = [0xAB; DIGEST_LEN];
        assert!(verify_path(&backend, &leaf, &[], 0, &leaf).is_ok());
    }

    // ---- construct helpers ----

    #[test]
    fn construct_root_single_leaf() {
        let backend = HostBackend::new();
        let leaves = [[0x42; DIGEST_LEN]];
        let root = construct_root(&backend, &leaves).unwrap();
        assert_eq!(root, leaves[0]);
    }

    #[test]
    fn construct_root_rejects_empty() {
        let backend = HostBackend::new();
        let empty: [[u8; DIGEST_LEN]; 0] = [];
        assert!(matches!(
            construct_root(&backend, &empty),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn construct_root_rejects_non_power_of_two() {
        let backend = HostBackend::new();
        let leaves: [[u8; DIGEST_LEN]; 3] = [[0; 32], [0; 32], [0; 32]];
        assert!(matches!(
            construct_root(&backend, &leaves),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }
}
