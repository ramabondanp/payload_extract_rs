use std::cell::RefCell;

thread_local! {
    static DECOMPRESS_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Execute a closure with a thread-local reusable buffer.
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
