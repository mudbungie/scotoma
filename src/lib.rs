//! Scotoma: a blind spot for agents.
//!
//! **S**ecure **C**redential **O**perations **T**hrough **O**paque
//! **M**ediated **A**ccess. Secrets are encrypted at rest under a password.
//! The user unlocks the vault into one resident process, which alone holds
//! the key. A model writes `[scotoma:NAME]` where a secret belongs; the
//! harness has the resident process run the command with the value swapped
//! in, and guards everything on its way to the model.
//!
//! ```no_run
//! # fn main() -> Result<(), scotoma::Error> {
//! // Somewhere, the user has run `scotoma unlock` on this directory.
//! let vault = scotoma::Scotoma::open("/home/u/.local/share/scotoma", "my-harness")?;
//!
//! // The user approves this at the resident process's console.
//! let vault = vault.clone().with_grant(&vault.grant("1h", &["api-password"])?);
//!
//! // The model wrote the placeholder. The resident process runs the command;
//! // the value never comes here.
//! let (mut out, mut err) = (Vec::new(), Vec::new());
//! let command = ["curl", "-u", "admin:[scotoma:api-password]", "https://example.com"];
//! vault.run(&command, &mut out, &mut err)?;
//!
//! // Last gate before the model: a secret in the request is an error.
//! vault.check("the request body")?;
//! # Ok(())
//! # }
//! ```
//!
//! Detection is exact string matching. See the README for what that does
//! and does not protect against.

mod admit;
mod audit;
mod client;
mod crypt;
mod error;
mod exec;
mod grant;
mod resident;
mod store;
mod table;
#[cfg(test)]
mod testing;
mod vault;
mod wire;

pub use client::{Scotoma, Stream};
pub use error::Error;
pub use resident::{Console, unlock};
