use std::cell::RefCell;

use anyhow::Result;

thread_local! {
    static EXTENT_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Fallibly reserve `min_capacity` bytes in `buf`, returning a clean error instead
/// of aborting the process via the global allocation-failure handler.
#[inline]
fn ensure_capacity(buf: &mut Vec<u8>, min_capacity: usize) -> Result<()> {
    let cap = buf.capacity();
    if cap < min_capacity {
        buf.try_reserve(min_capacity - cap).map_err(|_| {
            anyhow::anyhow!("out of memory: failed to reserve {min_capacity} bytes")
        })?;
    }
    Ok(())
}

/// Execute a closure with a thread-local reusable buffer for extent reads.
/// Separate from the decompression buffer to avoid conflicts when both are
/// needed in the same operation (e.g., SOURCE_BSDIFF reads extents then patches).
#[inline]
pub fn with_extent_buffer<F, R>(min_capacity: usize, f: F) -> Result<R>
where
    F: FnOnce(&mut Vec<u8>) -> Result<R>,
{
    EXTENT_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();
        ensure_capacity(&mut buf, min_capacity)?;
        f(&mut buf)
    })
}

/// Fallibly allocate a zero-filled buffer of `len` bytes, returning `Err` on
/// allocation failure instead of aborting. Use for one-off buffers whose size is
/// derived from untrusted payload metadata.
pub fn try_alloc_zeroed(len: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(len)
        .map_err(|_| anyhow::anyhow!("out of memory: failed to allocate {len} bytes"))?;
    v.resize(len, 0);
    Ok(v)
}

/// Fallibly create an empty buffer with reserved capacity, returning `Err` on
/// allocation failure instead of aborting.
pub fn try_alloc_capacity(cap: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve(cap)
        .map_err(|_| anyhow::anyhow!("out of memory: failed to reserve {cap} bytes"))?;
    Ok(v)
}
