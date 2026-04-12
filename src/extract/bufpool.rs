use std::cell::RefCell;

thread_local! {
    static DECOMPRESS_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static EXTENT_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Execute a closure with a thread-local reusable buffer for decompression.
/// The buffer is cleared before use but retains its capacity across calls,
/// eliminating per-operation heap allocations.
#[inline]
pub fn with_buffer<F, R>(min_capacity: usize, f: F) -> R
where
    F: FnOnce(&mut Vec<u8>) -> R,
{
    DECOMPRESS_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();
        let cap = buf.capacity();
        if cap < min_capacity {
            buf.reserve(min_capacity - cap);
        }
        f(&mut buf)
    })
}

/// Execute a closure with a thread-local reusable buffer for extent reads.
/// Separate from the decompression buffer to avoid conflicts when both are
/// needed in the same operation (e.g., SOURCE_BSDIFF reads extents then patches).
#[inline]
pub fn with_extent_buffer<F, R>(min_capacity: usize, f: F) -> R
where
    F: FnOnce(&mut Vec<u8>) -> R,
{
    EXTENT_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();
        let cap = buf.capacity();
        if cap < min_capacity {
            buf.reserve(min_capacity - cap);
        }
        f(&mut buf)
    })
}
