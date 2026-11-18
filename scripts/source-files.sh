#!/usr/bin/env bash
# The one home for "what is scotoma's source", newline-delimited on stdout.
# An allow-list of languages: Rust, and the shell of the gates themselves
# (`.githooks/` scripts carry no extension). Docs and config have no line cap.
# A new source language belongs in the list below and nowhere else.
set -euo pipefail
git ls-files '*.rs' '*.sh' '.githooks/*'
