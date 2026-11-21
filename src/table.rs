//! The one mechanism: a streaming find-and-replace over a fixed table.
//!
//! Substitution (placeholder -> secret value) and redaction (secret value ->
//! marker) are the same machine with different tables. Matching is
//! leftmost-longest and exact, and a match may straddle any chunk boundary:
//! bytes that could still begin a match are held until the next chunk (or the
//! end) decides them.

/// One replacement, and what to write in the audit log when it fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub find: Vec<u8>,
    pub put: Vec<u8>,
    pub secret: String,
}

/// What the table says about the text starting at one position.
#[derive(Debug, PartialEq, Eq)]
enum Scan {
    /// No entry begins here.
    Miss,
    /// The longest entry that begins here (an index into the table).
    Hit(usize),
    /// The text ran out while a longer entry could still match; the payload is
    /// the longest entry matched so far, if any.
    Partial(Option<usize>),
}

/// The streaming replacer. Feed it chunks; it returns what is safe to emit.
#[derive(Debug, Clone)]
pub(crate) struct Filter {
    /// Sorted by `find`, unique, none empty: a sorted array walked as a trie.
    entries: Vec<Entry>,
    held: Vec<u8>,
}

impl Filter {
    pub fn new(mut entries: Vec<Entry>) -> Self {
        entries.retain(|entry| !entry.find.is_empty());
        entries.sort_by(|a, b| a.find.cmp(&b.find));
        entries.dedup_by(|b, a| a.find == b.find);
        Self {
            entries,
            held: Vec::new(),
        }
    }

    /// Consume `chunk`. Returns the bytes now decided and the entries that
    /// fired, in order. With `last`, nothing is held back.
    pub fn feed(&mut self, chunk: &[u8], last: bool) -> (Vec<u8>, Vec<Entry>) {
        self.held.extend_from_slice(chunk);
        let text = std::mem::take(&mut self.held);
        let mut out = Vec::with_capacity(text.len());
        let mut fired = Vec::new();
        let mut rest = text.as_slice();
        while let Some((&first, tail)) = rest.split_first() {
            let hit = match self.scan(rest) {
                Scan::Partial(_) if !last => break,
                Scan::Hit(index) | Scan::Partial(Some(index)) => self.entries.get(index),
                Scan::Miss | Scan::Partial(None) => None,
            };
            if let Some(entry) = hit {
                out.extend_from_slice(&entry.put);
                fired.push(entry.clone());
                rest = rest.get(entry.find.len()..).unwrap_or_default();
            } else {
                out.push(first);
                rest = tail;
            }
        }
        self.held = rest.to_vec();
        (out, fired)
    }

    /// Narrow the sorted table one byte of `text` at a time: after byte `k`
    /// the range is exactly the entries that agree with `text` through `k`,
    /// and an entry that ends there sorts first in it.
    fn scan(&self, text: &[u8]) -> Scan {
        let mut range = self.entries.as_slice();
        let mut base = 0;
        let mut best = None;
        for (k, &byte) in text.iter().enumerate() {
            let lo = range.partition_point(|e| e.find.get(k).is_none_or(|&b| b < byte));
            let hi = range.partition_point(|e| e.find.get(k).is_none_or(|&b| b <= byte));
            range = range.get(lo..hi).unwrap_or_default();
            base += lo;
            match range.first() {
                None => return best.map_or(Scan::Miss, Scan::Hit),
                Some(entry) if entry.find.len() == k + 1 => best = Some(base),
                Some(_) => {}
            }
        }
        if range.iter().any(|entry| entry.find.len() > text.len()) {
            Scan::Partial(best)
        } else {
            best.map_or(Scan::Miss, Scan::Hit)
        }
    }
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
