// Relay port allocation pool for TURN allocations
//
// Manages a pool of UDP port numbers available for TURN relay transport
// addresses. Each TURN allocation requires a dedicated relay port.
//
// The pool pre-shuffles available ports on creation to avoid predictable
// allocation patterns. Ports are allocated from the front of the queue
// and returned to the back on release.
//
// Default range: 49152-65535 (IANA dynamic/private port range)
// This gives approximately 16,383 relay ports.

use std::collections::HashSet;

/// Manages a pool of available relay port numbers.
///
/// Ports are pre-shuffled on construction to avoid predictable patterns.
/// Allocation is O(1) from a Vec (pop), release is O(1) (push).
///
/// # Example
///
/// ```
/// use relay::turn::port_pool::PortPool;
///
/// let mut pool = PortPool::new(49152, 49160);
/// assert_eq!(pool.available_count(), 9); // 49152..=49160 inclusive
///
/// let port = pool.allocate().unwrap();
/// assert!(port >= 49152 && port <= 49160);
/// assert_eq!(pool.available_count(), 8);
///
/// pool.release(port);
/// assert_eq!(pool.available_count(), 9);
/// ```
#[derive(Debug, Clone)]
pub struct PortPool {
    /// Ports available for allocation (shuffled on construction).
    available: Vec<u16>,
    /// Currently allocated ports (for tracking and preventing double-release).
    allocated: HashSet<u16>,
}

impl PortPool {
    /// Create a new port pool with ports in the range `[range_start, range_end]` inclusive.
    ///
    /// The available ports are shuffled using a simple Fisher-Yates-like shuffle
    /// seeded from the system clock. For cryptographic randomness, use the
    /// `rand` crate version below.
    ///
    /// # Panics
    ///
    /// Panics if `range_start > range_end`.
    pub fn new(range_start: u16, range_end: u16) -> Self {
        assert!(
            range_start <= range_end,
            "range_start ({}) must be <= range_end ({})",
            range_start,
            range_end
        );

        let mut available: Vec<u16> = (range_start..=range_end).collect();

        // Shuffle using a simple PRNG seeded from system time.
        // This is sufficient for port randomization (not security-critical).
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut state = seed as u64;
        let len = available.len();
        if len > 1 {
            for i in (1..len).rev() {
                // Simple xorshift64 PRNG
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let j = (state as usize) % (i + 1);
                available.swap(i, j);
            }
        }

        PortPool {
            available,
            allocated: HashSet::new(),
        }
    }

    /// Allocate a port from the pool.
    ///
    /// Returns `None` if no ports are available.
    /// Allocated ports are tracked to prevent double-allocation.
    pub fn allocate(&mut self) -> Option<u16> {
        let port = self.available.pop()?;
        self.allocated.insert(port);
        Some(port)
    }

    /// Release a previously allocated port back to the pool.
    ///
    /// If the port was not currently allocated (double-release or unknown port),
    /// this is a no-op to prevent pool corruption.
    pub fn release(&mut self, port: u16) {
        if self.allocated.remove(&port) {
            self.available.push(port);
        }
    }

    /// Returns the number of ports currently available for allocation.
    pub fn available_count(&self) -> usize {
        self.available.len()
    }

    /// Returns the number of ports currently allocated.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Returns the total capacity of the pool (available + allocated).
    pub fn total_capacity(&self) -> usize {
        self.available.len() + self.allocated.len()
    }

    /// Returns `true` if the given port is currently allocated.
    pub fn is_allocated(&self, port: u16) -> bool {
        self.allocated.contains(&port)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pool_correct_count() {
        let pool = PortPool::new(49152, 49160);
        assert_eq!(pool.available_count(), 9); // 49152..=49160 inclusive
        assert_eq!(pool.allocated_count(), 0);
        assert_eq!(pool.total_capacity(), 9);
    }

    #[test]
    fn test_single_port_pool() {
        let mut pool = PortPool::new(5000, 5000);
        assert_eq!(pool.available_count(), 1);

        let port = pool.allocate().unwrap();
        assert_eq!(port, 5000);
        assert_eq!(pool.available_count(), 0);
        assert!(pool.is_allocated(5000));

        assert!(pool.allocate().is_none());

        pool.release(5000);
        assert_eq!(pool.available_count(), 1);
        assert!(!pool.is_allocated(5000));
    }

    #[test]
    fn test_allocate_all_ports() {
        let mut pool = PortPool::new(10000, 10004);
        let mut allocated = Vec::new();

        for _ in 0..5 {
            let port = pool.allocate().unwrap();
            assert!((10000..=10004).contains(&port));
            allocated.push(port);
        }

        assert_eq!(pool.available_count(), 0);
        assert_eq!(pool.allocated_count(), 5);
        assert!(pool.allocate().is_none());

        // All ports should be unique
        let unique: HashSet<u16> = allocated.iter().copied().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn test_release_and_reallocate() {
        let mut pool = PortPool::new(8000, 8002);

        let p1 = pool.allocate().unwrap();
        let p2 = pool.allocate().unwrap();
        let p3 = pool.allocate().unwrap();
        assert!(pool.allocate().is_none());

        pool.release(p2);
        assert_eq!(pool.available_count(), 1);

        let p4 = pool.allocate().unwrap();
        assert_eq!(p4, p2); // released port gets reused
        assert!(pool.allocate().is_none());

        pool.release(p1);
        pool.release(p3);
        pool.release(p4);
        assert_eq!(pool.available_count(), 3);
    }

    #[test]
    fn test_double_release_is_noop() {
        let mut pool = PortPool::new(7000, 7002);

        let port = pool.allocate().unwrap();
        pool.release(port);
        assert_eq!(pool.available_count(), 3);

        // Double release should not add a duplicate
        pool.release(port);
        assert_eq!(pool.available_count(), 3);
    }

    #[test]
    fn test_release_unknown_port_is_noop() {
        let mut pool = PortPool::new(7000, 7002);

        // Release a port that was never allocated
        pool.release(9999);
        assert_eq!(pool.available_count(), 3);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    #[should_panic(expected = "range_start")]
    fn test_invalid_range_panics() {
        let _ = PortPool::new(100, 50);
    }

    #[test]
    fn test_large_pool() {
        let pool = PortPool::new(49152, 65535);
        assert_eq!(pool.available_count(), 16384);
        assert_eq!(pool.total_capacity(), 16384);
    }

    #[test]
    fn test_is_allocated() {
        let mut pool = PortPool::new(6000, 6005);

        let port = pool.allocate().unwrap();
        assert!(pool.is_allocated(port));

        pool.release(port);
        assert!(!pool.is_allocated(port));

        // Never-allocated port
        assert!(!pool.is_allocated(9999));
    }
}
