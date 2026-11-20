# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- **The vault is encrypted and locked.** Secrets are sealed with
  XChaCha20-Poly1305 under a vault key that is itself sealed under an
  Argon2id stretch of a password. `scotoma unlock` (library:
  `scotoma::unlock`) holds the key in one resident process; every other
  invocation and `Scotoma` itself are now clients of it and fail with
  `Error::Locked` otherwise. **A 0.0.1 vault is not read:** remove its
  `secrets/` directory and set the secrets again.
- **Grants.** `scotoma grant DURATION [NAME...]` / `Scotoma::grant` asks the
  person at the unlock terminal; on `y` it returns a token (`SCOTOMA_GRANT`,
  `Scotoma::with_grant`). Issuing, substituting and running need one.
- **The resident process runs the command.** `scotoma run` / `Scotoma::run`
  no longer bring the value to the caller, and a value that went in through
  a handle comes back out as that handle.
- **The outbound guard.** `Scotoma::guard()` / `check()` and `scotoma guard`
  pass clean content through and fail with `Error::Leak` at the first stored
  secret value, logging a `leak` event: the gate in front of a model request.
- The usage log gains a sixth column, the grant id.

## [0.0.1]

- The vault: secrets as private files, an append-only usage log, and handles
  that are valid because the log says they were issued.
- `Scotoma::substitute` / `redact` and their streaming forms.
- The `scotoma` command: `set`, `rm`, `ls`, `issue`, `sub`, `redact`, `run`.
