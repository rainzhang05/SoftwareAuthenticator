//! Heap allocations wiped before they are returned to the wrapped allocator.

use std::{
    alloc::{GlobalAlloc, Layout},
    mem::MaybeUninit,
    ptr, slice,
};

use zeroize::Zeroize;

/// An allocator that wipes every block before releasing it.
///
/// Reallocation always moves the block, so shrinking cannot release an
/// unwiped tail and growing cannot leave a copy in the old allocation.
pub struct WipingAllocator<A>(A);

impl<A> WipingAllocator<A> {
    /// Wrap `allocator`, without changing its sizes or alignments.
    pub const fn new(allocator: A) -> Self {
        Self(allocator)
    }
}

// SAFETY: allocation delegates unchanged layouts. Deallocation wipes only
// the owned block, then releases it with its original layout. Reallocation
// preserves the prefix and leaves the old block alone on failure. These
// methods neither allocate through themselves nor unwind.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid, non-zero allocation layout.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid, non-zero allocation layout.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: deallocation transfers exclusive ownership of this entire
        // block. Its layout bounds the slice within one allocation and below
        // isize::MAX. MaybeUninit accepts even bytes never initialized by the
        // caller; zeroize writes them without reading their previous values.
        unsafe {
            slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u8>>(), layout.size()).zeroize();
        }
        // SAFETY: the pointer and layout still describe the wrapped
        // allocator's original block, now wiped.
        unsafe { self.0.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return ptr::null_mut();
        };
        // SAFETY: realloc's caller supplies a non-zero new size and the
        // original alignment; the checked layout satisfies alloc's contract.
        let replacement = unsafe { self.alloc(new_layout) };
        if !replacement.is_null() {
            // SAFETY: both blocks are live and disjoint. This copies at most
            // either block's size, including any uninitialized bytes, without
            // reading them as Rust values.
            unsafe { ptr::copy_nonoverlapping(ptr, replacement, layout.size().min(new_size)) };
            // SAFETY: the caller transferred the original block and layout;
            // its prefix has been copied, so it can now be wiped and freed.
            unsafe { self.dealloc(ptr, layout) };
        }
        replacement
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{alloc::System, sync::Mutex};

    #[derive(Default)]
    struct RecordingAllocator {
        freed: Mutex<Vec<Vec<u8>>>,
        fail: bool,
    }

    // SAFETY: System owns every returned block. The recorder observes only
    // blocks surrendered to dealloc, before releasing them to System.
    unsafe impl GlobalAlloc for RecordingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if self.fail {
                return ptr::null_mut();
            }
            // SAFETY: the layout comes unchanged from the caller.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the layout comes unchanged from the caller.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: WipingAllocator initialized the whole owned block to
            // zero before handing it here; it remains live until System frees
            // it below. The recorder is not the test binary's global allocator.
            let bytes = unsafe { slice::from_raw_parts(ptr, layout.size()) }.to_vec();
            self.freed.lock().unwrap().push(bytes);
            // SAFETY: System allocated this block with this same layout.
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    fn check(old_size: usize, new_size: Option<usize>, alignment: usize) {
        let allocator = WipingAllocator::new(RecordingAllocator::default());
        let layout = Layout::from_size_align(old_size, alignment).unwrap();
        // SAFETY: a valid non-zero layout; every successful allocation below
        // is initialized before inspection and freed with its own layout.
        unsafe {
            let original = allocator.alloc(layout);
            assert!(!original.is_null());
            assert_eq!(original as usize % alignment, 0);
            ptr::write_bytes(original, 0xa5, old_size);
            if let Some(size) = new_size {
                let replacement = allocator.realloc(original, layout, size);
                assert!(!replacement.is_null());
                assert_ne!(original, replacement);
                assert_eq!(replacement as usize % alignment, 0);
                assert!(
                    slice::from_raw_parts(replacement, size.min(old_size))
                        .iter()
                        .all(|&byte| byte == 0xa5)
                );
                // Leave the new tail uninitialized: wiping must handle it.
                allocator.dealloc(
                    replacement,
                    Layout::from_size_align(size, alignment).unwrap(),
                );
            } else {
                allocator.dealloc(original, layout);
            }
        }
        let freed = allocator.0.freed.lock().unwrap();
        assert_eq!(freed.len(), if new_size.is_some() { 2 } else { 1 });
        assert_eq!(freed[0].len(), old_size);
        if let Some(size) = new_size {
            assert_eq!(freed[1].len(), size);
        }
        assert!(freed.iter().flatten().all(|&byte| byte == 0));
    }

    #[test]
    fn deallocation_wipes_the_whole_block() {
        check(257, None, 8);
    }

    #[test]
    fn growing_reallocation_wipes_both_blocks() {
        check(257, Some(1025), 8);
    }

    #[test]
    fn shrinking_reallocation_wipes_the_discarded_tail_too() {
        check(1025, Some(257), 8);
    }

    #[test]
    fn large_alignments_survive_allocation_and_reallocation() {
        check(257, None, 4096);
        check(257, Some(1025), 4096);
        check(1025, Some(257), 4096);
    }

    #[test]
    fn zeroed_allocation_preserves_the_wrapped_allocator_s_behavior() {
        let allocator = WipingAllocator::new(RecordingAllocator::default());
        let layout = Layout::from_size_align(257, 4096).unwrap();
        // SAFETY: the layout is non-zero, alloc_zeroed initializes its entire
        // block, and dealloc receives the same pointer and layout.
        unsafe {
            let ptr = allocator.alloc_zeroed(layout);
            assert!(!ptr.is_null());
            assert_eq!(ptr as usize % 4096, 0);
            assert!(
                slice::from_raw_parts(ptr, layout.size())
                    .iter()
                    .all(|&b| b == 0)
            );
            allocator.dealloc(ptr, layout);
        }
        assert_eq!(allocator.0.freed.lock().unwrap()[0], vec![0; 257]);
    }

    #[test]
    fn failed_reallocation_preserves_the_original_block() {
        let mut allocator = WipingAllocator::new(RecordingAllocator::default());
        let layout = Layout::from_size_align(257, 8).unwrap();
        // SAFETY: the valid allocation is initialized before inspection. A
        // failed realloc leaves it live, and it is freed with the same layout.
        unsafe {
            let ptr = allocator.alloc(layout);
            assert!(!ptr.is_null());
            ptr::write_bytes(ptr, 0xa5, layout.size());
            allocator.0.fail = true;
            assert!(allocator.realloc(ptr, layout, 1025).is_null());
            assert!(allocator.0.freed.lock().unwrap().is_empty());
            assert!(
                slice::from_raw_parts(ptr, layout.size())
                    .iter()
                    .all(|&b| b == 0xa5)
            );
            allocator.dealloc(ptr, layout);
        }
        assert!(allocator.0.freed.lock().unwrap()[0].iter().all(|&b| b == 0));
    }
}
