# scotoma

[![CI](https://github.com/mudbungie/scotoma/actions/workflows/release-plz.yml/badge.svg)](https://github.com/mudbungie/scotoma/actions/workflows/release-plz.yml)

A blind spot for agents: store secrets, hand out opaque handles, substitute
the value only at execution, and redact it from everything the model could
read.

*Scotoma*: a blind spot in the visual field. **S**ecure **C**redential
**O**perations **T**hrough **O**paque **M**ediated **A**ccess.

An agent that needs a password should be able to *use* it without ever
*seeing* it. With scotoma the model asks for a secret by name and receives a
random UUID (a *handle*). It writes the handle wherever the secret should go.
The harness swaps the real value in at the last moment before execution,
replaces the value with `[scotoma:NAME]` in anything on its way back to the
model, and every one of those acts lands in a usage log.

```console
$ printf 'hunter2' | scotoma set api-password
$ scotoma issue api-password
3f0c5e0a-8a55-4c1e-9d0b-6a1f8f0e2b7d
$ scotoma run curl -u admin:3f0c5e0a-8a55-4c1e-9d0b-6a1f8f0e2b7d https://example.com/login
$ scotoma run sh -c 'echo "the password is $1"' sh 3f0c5e0a-8a55-4c1e-9d0b-6a1f8f0e2b7d
the password is [scotoma:api-password]
```

## Install

```console
$ cargo install scotoma
```

Unix only (it relies on file modes and `/dev/urandom`). No dependencies
beyond the Rust standard library.

## Command line

```text
usage: scotoma COMMAND

  set NAME          store the secret read from stdin (one trailing newline dropped)
  rm NAME           delete a secret
  ls                list secret names
  issue NAME        print a new handle for a secret
  sub               copy stdin to stdout, each handle replaced by its secret
  redact            copy stdin to stdout, each secret value replaced by [scotoma:NAME]
  run CMD [ARG...]  run CMD with handles in its arguments replaced by their
                    secrets, and its stdout and stderr redacted

environment:
  SCOTOMA_HOME      the vault directory (default: $XDG_DATA_HOME/scotoma,
                    else $HOME/.local/share/scotoma)
  SCOTOMA_ACTOR     who the usage log says did it (default: $USER)

exit: 0 done, 1 failed, 2 usage; `run` exits as CMD did.
```

`sub` and `redact` are streaming filters: output is flushed as it is decided,
and a match that straddles two reads is still a match. A secret value is
never accepted or printed as an argument, only through stdin.

## Library

```rust
let vault = scotoma::Scotoma::open(home, "my-harness")?;
vault.set("api-password", "hunter2")?;

let handle = vault.issue("api-password")?;          // safe to show a model
let command = vault.substitute(&model_command)?;    // carries the secret: execute, never store
let shown = vault.redact(&command_output)?;         // safe to show a model
```

`Scotoma::substituter()` and `Scotoma::redactor()` return a `Stream`
(`push(&[u8])`, `finish()`) for data that arrives in pieces. That is the whole
API. A vault caches nothing, so any number of processes can share one: a
handle issued in one process substitutes in another.

## How it works

- **Secrets** are one file each, `secrets/NAME`, mode 0600 in a 0700
  directory. The name is the path.
- **The usage log** is `audit.tsv`, append-only, one line per act:
  `unix-seconds  actor  event  secret-name  handle`. Events are `set`,
  `remove`, `issue`, `use` (a handle was replaced by a value) and `redact` (a
  value was caught on its way out).
- **Handles** are stored nowhere else. A handle is valid because its `issue`
  line is in the log, and it stands for the secret's *current* value until the
  secret is removed.
- **Matching is exact**, leftmost-longest. Redaction also matches a value as
  it reads inside a JSON string, so a serialized request body can be scanned.
- **A use is logged before its bytes are released.** If the log cannot be
  written, nothing is substituted.

## What it does not do

Scotoma keeps a secret out of a model's context when the harness mediates
every path. It is a blind spot, not a sandbox:

- **Exact matches only.** A value that comes back transformed is not caught:
  base64 (`curl -v` prints a Basic-auth header that way), hex, URL-encoding,
  or one character per line.
- **Not encrypted at rest.** File permissions are the only protection on
  disk. A process running as the same user can read the vault; an agent with
  an unrestricted shell can too, though what it prints is still redacted.
- **Arguments are visible** to other local processes (`ps`) for the life of
  the command, as with any command-line credential.
- **A short secret redacts broadly.** Every occurrence of the value is
  replaced, wanted or not.

## Building

```console
$ make install-hooks    # one-time: seat .githooks/* in .git/hooks
$ make check            # the complete gate: size, leak-scan, fmt-check, lint, deny, cov
$ make test
$ make package          # build the .crate and leak-scan what it contains
```

## License

MIT OR Apache-2.0.
