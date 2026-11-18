+++
title = "Build scotoma v0: store, handles, substitution, redaction, audit log, CLI, gates, release"
created = 1794986452
updated = 1794986452
claimant = "Dickers"
root_commit = "6f0c1c5c92e733d9f48f9dbfd409ec4f6e27d9af"
+++
Lib + CLI secrets manager for agents. Store named secrets; issue opaque uuid handles; substitute handles into commands at execution; redact known secret values from streams; log usage. Repo gates modelled on frot/yog (bl-gate, 300-line cap, 100% coverage, leak scan, deny). Design lives in docs/DESIGN.md.