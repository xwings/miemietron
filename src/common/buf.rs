use crossbeam_queue::ArrayQueue;
use std::sync::Arc;

const DEFAULT_BUF_SIZE: usize = 4096;
const POOL_SIZE: usize = 1024;

/// A pool of reusable byte buffers to avoid allocation in the hot path.
pub struct BufferPool {
    pool: Arc<ArrayQueue<Vec<u8>>>,
    buf_size: usize,
}

impl BufferPool {
    pub fn new(buf_size: usize, pool_size: usize) -> Self {
        let pool = Arc::new(ArrayQueue::new(pool_size));
        // Pre-allocate some buffers
        for _ in 0..pool_size / 4 {
            let _ = pool.push(vec![0u8; buf_size]);
        }
        Self { pool, buf_size }
    }

    pub fn get(&self) -> PooledBuffer {
        let buf = self.pool.pop().unwrap_or_else(|| vec![0u8; self.buf_size]);
        PooledBuffer {
            buf,
            pool: self.pool.clone(),
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(DEFAULT_BUF_SIZE, POOL_SIZE)
    }
}

pub struct PooledBuffer {
    buf: Vec<u8>,
    pool: Arc<ArrayQueue<Vec<u8>>>,
}

impl PooledBuffer {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        buf.resize(buf.capacity(), 0);
        let _ = self.pool.push(buf);
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl std::ops::DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_buffer_from_pool() {
        let pool = BufferPool::new(8192, 16);
        let buf = pool.get();
        assert_eq!(buf.len(), 8192);
    }

    #[test]
    fn buffer_has_correct_default_size() {
        let pool = BufferPool::default();
        let buf = pool.get();
        assert_eq!(buf.len(), DEFAULT_BUF_SIZE);
    }

    #[test]
    fn buffer_as_slice_and_mut_slice() {
        let pool = BufferPool::new(64, 4);
        let mut buf = pool.get();
        assert_eq!(buf.as_slice().len(), 64);
        buf.as_mut_slice()[0] = 0xAB;
        assert_eq!(buf.as_slice()[0], 0xAB);
    }

    #[test]
    fn drop_returns_buffer_to_pool() {
        // Create a pool with capacity 4, pre-filled with 1 buffer (4/4 = 1).
        let pool = BufferPool::new(128, 4);
        // The pool pre-allocates pool_size/4 = 1 buffer.
        // Pop the pre-allocated one to start clean.
        let _initial = pool.pool.pop();

        // Get a buffer (pool is now empty, so it allocates a fresh one).
        let buf = pool.get();
        // Drop it -- it should be pushed back into the pool.
        drop(buf);

        // Now the pool should have exactly 1 buffer available.
        assert!(pool.pool.pop().is_some());
        assert!(pool.pool.pop().is_none());
    }

    #[test]
    fn deref_gives_access_to_slice() {
        let pool = BufferPool::new(32, 2);
        let buf = pool.get();
        // Deref should give us a &[u8] of length 32.
        let slice: &[u8] = &*buf;
        assert_eq!(slice.len(), 32);
    }
}
