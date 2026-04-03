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
