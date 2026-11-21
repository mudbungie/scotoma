//! Authorization: a grant is who may use which secrets, and within what
//! limits.
//!
//! Grants live only in the resident process's memory and die with it. A
//! grant has a public `id` (logged, shown) and is held by whoever knows its
//! token (never logged). A grant minted from another is bound by its own
//! limits and its parent's: every question below is asked of the whole chain,
//! so a child can never do what its parent cannot.

use crate::desk::Request;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub(crate) struct Grant {
    pub id: String,
    /// Who holds it, fixed when it was approved: its uses are logged under
    /// this name whatever the caller says. Empty leaves the caller's word.
    pub actor: String,
    /// The secrets it covers; empty means all of them.
    pub names: Vec<String>,
    /// Unix seconds after which it is dead.
    pub expires: u64,
    /// Uses left, counted down by every copy of this grant.
    pub left: Arc<AtomicU64>,
    /// Its holder may run commands but not be handed a value.
    pub run_only: bool,
    /// The grant this one was minted from.
    pub parent: Option<Arc<Grant>>,
}

/// What a grant request asks for. An absent limit is the largest number.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub seconds: u64,
    pub uses: u64,
    pub run_only: bool,
}

impl Grant {
    /// The standing permission for acts that reveal nothing: redaction and
    /// the guard run under this.
    pub fn none() -> Self {
        Self {
            id: "-".to_owned(),
            actor: String::new(),
            names: Vec::new(),
            expires: u64::MAX,
            left: Arc::new(AtomicU64::new(u64::MAX)),
            run_only: false,
            parent: None,
        }
    }

    pub fn mint(request: &Request, limits: &Limits, parent: Self) -> Self {
        Self {
            id: request.id.clone(),
            actor: request.actor.clone(),
            names: request.names.clone(),
            expires: now().saturating_add(limits.seconds),
            left: Arc::new(AtomicU64::new(limits.uses)),
            run_only: limits.run_only,
            parent: Some(Arc::new(parent)),
        }
    }

    fn up(&self, ask: fn(&Self) -> bool) -> bool {
        self.parent.as_deref().is_none_or(ask)
    }

    pub fn covers(&self, name: &str) -> bool {
        let own = self.names.is_empty() || self.names.iter().any(|covered| covered == name);
        own && self
            .parent
            .as_deref()
            .is_none_or(|parent| parent.covers(name))
    }

    pub fn live(&self) -> bool {
        now() < self.expires && self.left.load(Ordering::SeqCst) > 0 && self.up(Self::live)
    }

    /// Whether its holder may be handed a value (`sub`), not only run with one.
    pub fn reveals(&self) -> bool {
        !self.run_only && self.up(Self::reveals)
    }

    /// Spend one use, here and up the chain. False when none is left.
    pub fn charge(&self) -> bool {
        let spend = |left: u64| left.checked_sub(1);
        let paid = self
            .left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, spend);
        paid.is_ok() && self.up(Self::charge)
    }
}

/// `1h`, `3x`, `run`, or several joined by commas: a duration, a count of
/// uses, and whether the holder may only run commands.
pub(crate) fn limits(text: &str) -> Option<Limits> {
    let mut limits = Limits {
        seconds: u64::MAX,
        uses: u64::MAX,
        run_only: false,
    };
    for term in text.split(',') {
        match term.strip_suffix('x') {
            _ if term == "run" => limits.run_only = true,
            Some(count) => limits.uses = count.parse().ok()?,
            None => limits.seconds = seconds(term)?,
        }
    }
    Some(limits)
}

/// The limits as the person approving reads them.
pub(crate) fn describe(text: &str) -> String {
    let terms = text.split(',').map(|term| match term.strip_suffix('x') {
        _ if term == "run" => "run only".to_owned(),
        Some("1") => "1 use".to_owned(),
        Some(count) => format!("{count} uses"),
        None => term.to_owned(),
    });
    terms.collect::<Vec<_>>().join(", ")
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
