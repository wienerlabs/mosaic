//! Stack-bounded bump arena allocator.
//!
//! On Solana, the heap is a fixed-size frame requested via
//! `ComputeBudgetInstruction::request_heap_frame` (default 32 KiB, max 256 KiB).
//! Allocating from the global allocator at every step is wasteful; the bump
//! pattern lets us carve scratch space for MSM accumulators, SHA-256 absorb
//! buffers, and per-round transcript squeezings without any frees.
//!
//! This implementation is deliberately minimal:
//!
//! - Backing storage is supplied by the caller (typically a `[u8; N]` on the
//!   stack or a `Vec<u8>` allocated once at program entry).
//! - Allocations are aligned to the requested type's `align_of`.
//! - No deallocation; the arena is dropped wholesale at program exit.
//!
//! The pattern matches the eprint 2025/1741 STARK-on-Solana technique of
//! synchronizing the bump arena with the requested heap frame.

use crate::error::OnChainError;

/// A stack-bounded bump allocator. Owns no memory itself; wraps a caller-provided buffer.
///
/// # Borrow model
///
/// `forbid(unsafe_code)` rules out the `UnsafeCell` trick that `bumpalo` uses
/// to hand out multiple concurrent `&mut` references. So this arena offers
/// **single-borrow alloc**: each call to [`Self::alloc_slice`] returns a
/// `&mut [u8]` tied to `&mut self`, meaning you cannot keep two live arena
/// allocations simultaneously.
///
/// A real bump allocator (with `UnsafeCell`-backed multi-borrow) is tracked
/// by [issue #58](https://github.com/wienerlabs/mosaic/issues/58); it ships
/// behind an `unsafe-arena` feature flag with Miri CI as the lockstep
/// quality gate. The single-borrow API here remains the default.
///
/// `alloc_split` for multi-slice carving is tracked by
/// [issue #15](https://github.com/wienerlabs/mosaic/issues/15) — Phase 2
/// once we identify a verifier that needs two concurrent scratch buffers.
///
/// This is sufficient for typical verifier scratch patterns:
///
/// 1. Build pairing input → call syscall → drop the buffer.
/// 2. Build SHA-256 absorb buffer → hash → drop.
/// 3. Reset the cursor at the end of the verifier call.
///
/// # Example
///
/// ```ignore
/// let mut backing = [0u8; 1024];
/// let mut arena = BumpArena::new(&mut backing);
/// let scratch: &mut [u8] = arena.alloc_slice(64)?;
/// ```
pub struct BumpArena<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> BumpArena<'a> {
    /// Wrap `buffer` as a bump arena. Capacity == `buffer.len()`.
    #[must_use]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Total backing-store size in bytes.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Bytes consumed so far.
    #[must_use]
    pub const fn used(&self) -> usize {
        self.cursor
    }

    /// Bytes still available.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.cursor)
    }

    /// Reset cursor to zero. The borrow checker enforces that no live borrows
    /// into the arena exist when this is called (`&mut self`).
    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    /// Allocate a `len`-byte slice, aligned to `align` (power of two).
    pub fn alloc_aligned(&mut self, len: usize, align: usize) -> Result<&mut [u8], OnChainError> {
        debug_assert!(align.is_power_of_two(), "align must be a power of two");
        let mut start = self.cursor;
        let misalign = start & align.saturating_sub(1);
        if misalign != 0 {
            start = start.checked_add(align - misalign).ok_or(OnChainError::HeapExhausted)?;
        }
        let end = start.checked_add(len).ok_or(OnChainError::HeapExhausted)?;
        if end > self.buffer.len() {
            return Err(OnChainError::HeapExhausted);
        }
        self.cursor = end;
        self.buffer
            .get_mut(start..end)
            .ok_or(OnChainError::InternalInvariantViolation)
    }

    /// Allocate a `len`-byte slice with byte alignment.
    pub fn alloc_slice(&mut self, len: usize) -> Result<&mut [u8], OnChainError> {
        self.alloc_aligned(len, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_then_reset() {
        let mut backing = [0u8; 128];
        {
            let mut arena = BumpArena::new(&mut backing);
            let a = arena.alloc_slice(32).unwrap();
            assert_eq!(a.len(), 32);
            assert_eq!(arena.used(), 32);
            arena.reset();
            assert_eq!(arena.used(), 0);
        }
    }

    #[test]
    fn exhaustion_yields_error() {
        let mut backing = [0u8; 16];
        let mut arena = BumpArena::new(&mut backing);
        let _ = arena.alloc_slice(16).unwrap();
        assert!(matches!(
            arena.alloc_slice(1),
            Err(OnChainError::HeapExhausted),
        ));
    }
}
