//! Records waiting to be sent, bounded by count and by bytes.
//!
//! When either bound is reached the **oldest** record goes: a page left open
//! with the ingest down keeps what it said most recently, and never grows.

use std::collections::VecDeque;

pub(crate) struct Buffer {
    records: VecDeque<String>,
    bytes: usize,
    max_records: usize,
    max_bytes: usize,
    dropped: u64,
}

impl Buffer {
    pub(crate) const fn new(max_records: usize, max_bytes: usize) -> Self {
        Self {
            records: VecDeque::new(),
            bytes: 0,
            max_records,
            max_bytes,
            dropped: 0,
        }
    }

    /// Adds one encoded record, dropping the oldest until both bounds hold.
    /// A record larger than the whole byte bound is dropped itself.
    pub(crate) fn push(&mut self, record: String) {
        if record.len() > self.max_bytes {
            self.dropped += 1;
            return;
        }
        self.bytes += record.len();
        self.records.push_back(record);
        while self.records.len() > self.max_records || self.bytes > self.max_bytes {
            if let Some(oldest) = self.records.pop_front() {
                self.bytes -= oldest.len();
                self.dropped += 1;
            }
        }
    }

    /// Takes the oldest records, up to `max_records` and `max_bytes` of them.
    /// At least one record is taken when any is buffered, since every one
    /// fits within the buffer's own byte bound.
    pub(crate) fn take_batch(&mut self, max_records: usize, max_bytes: usize) -> Vec<String> {
        let mut batch = Vec::new();
        let mut size = 0;
        while let Some(next) = self.records.front() {
            if batch.len() == max_records || (!batch.is_empty() && size + next.len() > max_bytes) {
                break;
            }
            let record = self.records.pop_front().unwrap_or_default();
            size += record.len();
            self.bytes -= record.len();
            batch.push(record);
        }
        batch
    }

    pub(crate) fn clear(&mut self) {
        self.records.clear();
        self.bytes = 0;
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    #[cfg(test)]
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub(crate) const fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::Buffer;

    fn record(label: usize, size: usize) -> String {
        let prefix = label.to_string();
        format!("{prefix}{}", "x".repeat(size - prefix.len()))
    }

    #[test]
    fn the_count_bound_drops_the_oldest() {
        let mut buffer = Buffer::new(3, 10_000);
        for label in 0..5 {
            buffer.push(record(label, 10));
        }
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.dropped(), 2);
        let kept = buffer.take_batch(10, 10_000);
        assert_eq!(kept, [record(2, 10), record(3, 10), record(4, 10)]);
    }

    #[test]
    fn the_byte_bound_drops_the_oldest() {
        let mut buffer = Buffer::new(100, 25);
        buffer.push(record(0, 10));
        buffer.push(record(1, 10));
        buffer.push(record(2, 10));
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.bytes(), 20);
        assert_eq!(buffer.dropped(), 1);
        assert_eq!(buffer.take_batch(10, 1_000), [record(1, 10), record(2, 10)]);
        assert_eq!(buffer.bytes(), 0);
    }

    #[test]
    fn a_record_larger_than_the_buffer_is_dropped_on_arrival() {
        let mut buffer = Buffer::new(100, 25);
        buffer.push(record(0, 10));
        buffer.push(record(1, 26));
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.dropped(), 1);
    }

    #[test]
    fn a_batch_respects_its_own_bounds_and_leaves_the_rest() {
        let mut buffer = Buffer::new(100, 10_000);
        for label in 0..6 {
            buffer.push(record(label, 10));
        }
        assert_eq!(buffer.take_batch(4, 10_000).len(), 4);
        assert_eq!(buffer.len(), 2);
        let mut buffer = Buffer::new(100, 10_000);
        for label in 0..6 {
            buffer.push(record(label, 10));
        }
        assert_eq!(buffer.take_batch(100, 35).len(), 3);
        assert_eq!(
            buffer.take_batch(100, 5).len(),
            1,
            "one record always moves"
        );
        assert_eq!(buffer.len(), 2);
    }
}
