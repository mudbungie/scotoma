//! Authorization: a grant is who may use which secrets, and until when.
//!
//! Grants live only in the resident process's memory and die with it. A
//! grant has a public `id` (logged, shown) and is held by whoever knows its
//! token (never logged).

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub id: String,
    /// The secrets it covers; empty means all of them.
    pub names: Vec<String>,
    /// Unix seconds after which it is dead.
    pub expires: u64,
}

impl Grant {
    /// The standing permission for acts that reveal nothing: redaction and
    /// the guard run under this.
    pub fn none() -> Self {
        Self {
            id: "-".to_owned(),
            names: Vec::new(),
            expires: u64::MAX,
        }
    }

    pub fn covers(&self, name: &str) -> bool {
        self.names.is_empty() || self.names.iter().any(|covered| covered == name)
    }

    pub fn live(&self) -> bool {
        now() < self.expires
    }
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `30s`, `15m`, `1h`, `2d` as seconds.
pub(crate) fn seconds(text: &str) -> Option<u64> {
    let (count, unit) = text.split_at_checked(text.len().checked_sub(1)?)?;
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    count.parse::<u64>().ok()?.checked_mul(scale)
}

#[cfg(test)]
#[path = "grant_tests.rs"]
mod tests;
