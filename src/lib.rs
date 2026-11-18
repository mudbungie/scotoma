//! Scotoma: a blind spot for agents.
//!
//! **S**ecure **C**redential **O**perations **T**hrough **O**paque
//! **M**ediated **A**ccess. A harness stores secrets here, hands its model an
//! opaque handle instead of the value, swaps the value in only where a command
//! is executed, and redacts the value from everything the model could read.
//!
//! ```
//! # fn main() -> Result<(), scotoma::Error> {
//! # let home = std::env::temp_dir().join(format!("scotoma-doc-{}", std::process::id()));
//! let vault = scotoma::Scotoma::open(&home, "docs")?;
//! vault.set("api-password", "hunter2")?;
//!
//! // The model asks for the secret by name and gets a handle.
//! let handle = vault.issue("api-password")?;
//! let command = format!("curl -u admin:{handle} https://example.com");
//!
//! // The harness substitutes at the last moment, and redacts what comes back.
//! assert_eq!(vault.substitute(&command)?, "curl -u admin:hunter2 https://example.com");
//! assert_eq!(vault.redact("sent hunter2")?, "sent [scotoma:api-password]");
//! # std::fs::remove_dir_all(&home).ok();
//! # Ok(())
//! # }
//! ```
//!
//! Everything is exact string matching. See the README for what that does
//! and does not protect against.

mod audit;
mod error;
mod store;
mod table;
#[cfg(test)]
mod testing;
mod vault;

pub use error::Error;
pub use vault::{Scotoma, Stream};
