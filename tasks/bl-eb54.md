+++
title = "Locked vault: encryption at rest, resident process, grants (duration first)"
created = 1795054184
updated = 1795147202
claimant = "Dickers"
root_commit = "6f0c1c5c92e733d9f48f9dbfd409ec4f6e27d9af"
+++
Design: docs/DESIGN.md 'Next: the locked vault'. Blocked on the operator's answers to its three open decisions (post-quantum meaning; who executes; does a grant re-ask the password). Adds two cryptography dependencies and replaces the plaintext store; the library becomes a client of the resident process.

---

Operator answers 2026-11-19: (1) symmetric only — Argon2id + XChaCha20-Poly1305, no public-key scheme. (2) Support BOTH: the resident process runs the command itself ('scotoma run ...': value never crosses the socket, output redacted back to the handle the caller wrote), and a client may also receive substituted text. (3) Minting a grant needs an authorization step but not the password again: the resident process's own console asks y/N. Build: duration grants only; counted and subagent grants later.
