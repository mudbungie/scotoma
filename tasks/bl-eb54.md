+++
title = "Locked vault: encryption at rest, resident process, grants (duration first)"
created = 1795054184
updated = 1795054184
root_commit = "6f0c1c5c92e733d9f48f9dbfd409ec4f6e27d9af"
+++
Design: docs/DESIGN.md 'Next: the locked vault'. Blocked on the operator's answers to its three open decisions (post-quantum meaning; who executes; does a grant re-ask the password). Adds two cryptography dependencies and replaces the plaintext store; the library becomes a client of the resident process.