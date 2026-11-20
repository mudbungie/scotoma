# scotoma

[![CI](https://github.com/mudbungie/scotoma/actions/workflows/release-plz.yml/badge.svg)](https://github.com/mudbungie/scotoma/actions/workflows/release-plz.yml)

A blind spot for agents: store secrets, hand out opaque handles, substitute
the value only at execution, and redact it from everything the model could
read.

*Scotoma*: a blind spot in the visual field. **S**ecure **C**redential
**O**perations **T**hrough **O**paque **M**ediated **A**ccess.

An agent that needs a password should be able to *use* it without ever
*seeing* it. Secrets are encrypted on disk under your password. You unlock
the vault into one resident process, which alone holds the key, and you
approve who may use what, for how long. The model asks for a secret by name
and receives a random UUID (a *handle*). It writes the handle wherever the
secret should go; the resident process runs the command with the real value
swapped in, and anything the command prints has the value turned back into
the handle. Everything is logged.

In your terminal:

```console
$ scotoma unlock
password:
unlocked. Grant requests are asked here; `scotoma lock` ends this.
grant requested by my-agent: api-password for 1h
approve? [y/N] y
```

In the agent's:

```console
$ printf 'hunter2' | scotoma set api-password
$ export SCOTOMA_GRANT=$(scotoma grant 1h api-password)     # waits for your "y"
$ scotoma issue api-password
3f0c5e0a-8a55-4c1e-9d0b-6a1f8f0e2b7d
$ scotoma run curl -u admin:3f0c5e0a-8a55-4c1e-9d0b-6a1f8f0e2b7d https://example.com/login
$ scotoma run sh -c 'echo "the password is $1"' sh 3f0c5e0a-8a55-4c1e-9d0b-6a1f8f0e2b7d
the password is 3f0c5e0a-8a55-4c1e-9d0b-6a1f8f0e2b7d
$ echo 'about to send hunter2 to the model' | scotoma guard
scotoma: secret "api-password" found in outgoing content
```

## Install

```console
$ cargo install scotoma
```

Unix only (it relies on file modes, Unix sockets and `/dev/urandom`).

## Command line

```text
usage: scotoma COMMAND

  unlock            read the vault password and serve the vault from this
                    terminal until it is locked; a vault that does not exist
                    is created. Grant requests are approved here.
  lock              end the unlocked session; the key and all grants are gone

  grant DURATION [NAME...]
                    ask the person at the unlock terminal to let the caller
                    use the named secrets (none: all) for 30s, 15m, 1h, 2d...;
                    prints a token to put in SCOTOMA_GRANT

  set NAME          store the secret read from stdin (one trailing newline dropped)
  rm NAME           delete a secret
  ls                list secret names

  issue NAME        print a new handle for a secret                    [grant]
  run CMD [ARG...]  run CMD with each handle in its arguments replaced by
                    its secret; in its output the secret reads as the
                    handle again                                       [grant]
  sub               copy stdin to stdout, each handle replaced by its
                    secret                                             [grant]
  redact            copy stdin to stdout, each secret value replaced by [scotoma:NAME]
  guard             copy stdin to stdout; fail at the first secret value

environment:
  SCOTOMA_HOME      the vault directory (default: $XDG_DATA_HOME/scotoma,
                    else $HOME/.local/share/scotoma)
  SCOTOMA_ACTOR     who the usage log says did it (default: $USER)
  SCOTOMA_GRANT     the grant token for commands marked [grant]

exit: 0 done, 1 failed, 2 usage; `run` exits as CMD did.
```

`sub`, `redact` and `guard` are streaming filters: output is flushed as it is
decided, and a match that straddles two reads is still a match. A secret
value is never accepted or printed as an argument, only through stdin.

## Library

```rust
let vault = scotoma::Scotoma::open(home, "my-harness")?;        // a client; holds no key
let vault = vault.clone().with_grant(&vault.grant("1h", &["api-password"])?);

let handle = vault.issue("api-password")?;                      // safe to show a model
let code = vault.run(&["curl", "-u", &login], &mut out, &mut err)?;  // the value never comes here
let shown = vault.redact(&tool_output)?;                        // safe to show a model
vault.check(&request_body)?;                                    // Err(Leak) means: do not send
```

`redact` rewrites; `check` refuses. Redact what a tool printed, so the
transcript stays clean; check what is about to be sent to the model, so a
secret that got past everything else stops the request instead of leaving.

`run` keeps the value inside the resident process. When the harness must
execute the command itself, `substitute` returns the text with values in
place: that text carries secrets and must go only to the thing that executes.

`substituter()`, `redactor()` and `guard()` return a `Stream` (`push(&[u8])`,
`finish()`) for data that arrives in pieces. `scotoma::unlock(home, console)`
is the resident process itself, for a harness that wants to host it.

## How it works

- **At rest.** Each secret is one file, `secrets/NAME`, encrypted with
  XChaCha20-Poly1305 under a random 256-bit vault key and bound to its name.
  The vault key is stored in `key`, encrypted under a key stretched from your
  password with Argon2id. Symmetric cryptography only: there is no public key
  for a quantum computer to break.
- **Unlocked.** `scotoma unlock` holds the vault key in memory and serves
  the vault on a socket in the vault directory. Every other invocation, and
  the library, is a client. `scotoma lock`, or the process ending, forgets
  the key and every grant.
- **Grants.** Issuing a handle, substituting and running need a grant: a
  token for named secrets (or all) until a time. A grant is minted only when
  the person at the unlock terminal answers `y`. Redaction and the guard need
  none, so detection never lapses.
- **The usage log** is `audit.tsv`, append-only, one line per act:
  `unix-seconds  actor  event  secret-name  handle  grant-id`. Events are
  `set`, `remove`, `grant`, `issue`, `use` (a handle was replaced by a value),
  `redact` (a value was rewritten) and `leak` (a guard refused content). It
  holds names and identifiers, never a value or a grant token.
- **Handles** are stored nowhere else. A handle is valid because its `issue`
  line is in the log, and it stands for the secret's *current* value until
  the secret is removed.
- **Matching is exact**, leftmost-longest. Redaction and the guard also match
  a value as it reads inside a JSON string, so a serialized request body can
  be checked.
- **A use is authorized and logged before its bytes are released.** If the
  log cannot be written, nothing is substituted and no output is passed on.

## What it does not do

- **Exact matches only.** A value that comes back transformed is not caught:
  base64 (`curl -v` prints a Basic-auth header that way), hex, URL-encoding,
  or one character per line.
- **It is not a sandbox.** To a process running as you, the vault files are
  ciphertext, and the socket gives out no value without a grant. But it can
  store, replace, remove and list secrets, attach a debugger to the resident
  process, or read a grant token from the environment of whatever holds one. A grant is a bearer token: guard it like a password
  that expires.
- **Arguments are visible** to other local processes (`ps`) for the life of
  the command, as with any command-line credential.
- **A short secret redacts broadly.** Every occurrence of the value is
  replaced, wanted or not.
- **A forgotten password is a lost vault.** There is no recovery.

## Building

```console
$ make install-hooks    # one-time: seat .githooks/* in .git/hooks
$ make check            # the complete gate: size, leak-scan, fmt-check, lint, deny, cov
$ make test
$ make package          # build the .crate and leak-scan what it contains
```

## License

MIT OR Apache-2.0.
