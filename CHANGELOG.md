# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- **Detection knows encodings.** Redaction and the guard also catch a value
  percent-encoded and base64-encoded, including inside a longer base64 run
  such as a Basic-auth header.

- **The approver seat.** `unlock` prints an approver token: a grant over
  everything. Its holder answers grant requests (`scotoma pending`,
  `scotoma decide ID yes|no`; `Scotoma::pending`, `Scotoma::decide`) alongside
  the console, and `decide ID no` ends a live grant. `Console` now owns its
  streams.
- **A grant request names its secrets and gives a reason**:
  `scotoma grant LIMITS NAMES REASON...`, `Scotoma::grant(limits, names, reason)`.
- **A grant keeps the name it was asked under**; its uses are logged as that
  name.
- **Storing and removing a secret need a grant** over its name.
- **Every request is logged**: `request`, then `grant`, `refuse` or
  `abandon`, and `revoke`. A request whose caller hangs up no longer waits.

- **Name placeholders replace UUID handles.** A model writes
  `[scotoma:NAME]`; `issue` (`scotoma issue`, `Scotoma::issue`) is gone. The
  usage log's fifth and sixth columns are now the grant id and a note.

- **Grant limits.** `scotoma grant` / `Scotoma::grant` take comma-joined
  limits in place of a duration: a duration (`1h`), a count of uses (`3x`)
  and `run` (the holder may run commands but `sub` is refused). `1h` means
  what it did.
- **Grants minted from a grant.** A grant request that presents a grant is
  answered by it, without asking at the console: the new grant is bound by
  its parent's limits as well as its own. The usage log names the parent in
  the handle column of the `grant` line.

## [0.0.2]

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
