# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- **The outbound guard.** `Scotoma::guard()` / `check()` and `scotoma guard`
  pass clean content through and fail with `Error::Leak` at the first stored
  secret value, logging a `leak` event: the gate in front of a model request.

## [0.0.1]

- The vault: secrets as private files, an append-only usage log, and handles
  that are valid because the log says they were issued.
- `Scotoma::substitute` / `redact` and their streaming forms.
- The `scotoma` command: `set`, `rm`, `ls`, `issue`, `sub`, `redact`, `run`.
