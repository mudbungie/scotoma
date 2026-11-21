# scotoma

[![CI](https://github.com/mudbungie/scotoma/actions/workflows/release-plz.yml/badge.svg)](https://github.com/mudbungie/scotoma/actions/workflows/release-plz.yml)

A blind spot for agents: store secrets, let a model name them, substitute
the value only at execution, and redact it from everything the model could
read.

*Scotoma*: a blind spot in the visual field. **S**ecure **C**redential
**O**perations **T**hrough **O**paque **M**ediated **A**ccess.

An agent that needs a password should be able to *use* it without ever
*seeing* it. Secrets are encrypted on disk under your password. You unlock
the vault into one resident process, which alone holds the key, and you
approve who may use what, for how long. The model writes
`[scotoma:NAME]` wherever a secret should go; the resident process runs the
command with the real value swapped in, and anything the command prints has
the value turned back into `[scotoma:NAME]`. Everything is logged.

In your terminal:

```console
$ scotoma unlock
password:
approver token: 0b9f6c1e-52a7-4d0c-9a57-3d1c2f4e8a10
unlocked. Grant requests are asked here; `scotoma lock` ends this.
grant requested by my-agent: api-password for 1h, run only
reason: log in to the staging site
approve? [y/N] y
```

The approver token is yours: it stores secrets and answers requests.

```console
$ export SCOTOMA_GRANT=0b9f6c1e-52a7-4d0c-9a57-3d1c2f4e8a10
$ printf 'hunter2' | scotoma set api-password
```

In the agent's:

```console
$ export SCOTOMA_ACTOR=my-agent
$ export SCOTOMA_GRANT=$(scotoma grant 1h,run api-password log in to the staging site)
$ scotoma run curl -u 'admin:[scotoma:api-password]' https://example.com/login
$ scotoma run sh -c 'echo "the password is $1"' sh '[scotoma:api-password]'
the password is [scotoma:api-password]
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
                    is created. Prints the approver token, and asks each
                    grant request here.
  lock              end the unlocked session; the key and all grants are gone

  grant LIMITS NAMES REASON...
                    ask for a grant over NAMES (joined by commas), saying
                    why; prints a token to put in SCOTOMA_GRANT. LIMITS joins
                    with commas any of:
                      30s, 15m, 1h, 2d   how long it lasts
                      3x                 how many commands or streams may
                                         use a secret
                      run                `run` only: `sub` is refused
                    as in `1h`, `1x,run` or `15m,3x`. An approver decides.
                    With SCOTOMA_GRANT set nobody is asked: the new grant is
                    minted from that one and can do nothing that one cannot.
                    Hand it to a subagent.
  pending           wait for grant requests and print them, one per line:
                    ID, who, names, limits, reason             [approver]
  decide ID yes|no  answer a request; `no` also ends a live grant and
                    every grant minted from it                 [approver]

  set NAME          store the secret read from stdin (one trailing newline
                    dropped)                                           [grant]
  rm NAME           delete a secret                                    [grant]
  ls                list secret names

  run CMD [ARG...]  run CMD with each [scotoma:NAME] in its arguments
                    replaced by that secret; in its output the secret reads
                    as [scotoma:NAME] again                            [grant]
  sub               copy stdin to stdout, each [scotoma:NAME] replaced by
                    that secret                                        [grant]
  redact            copy stdin to stdout, each secret value replaced by [scotoma:NAME]
  guard             copy stdin to stdout; fail at the first secret value

environment:
  SCOTOMA_HOME      the vault directory (default: $XDG_DATA_HOME/scotoma,
                    else $HOME/.local/share/scotoma)
  SCOTOMA_ACTOR     who is asking (default: $USER). A grant keeps the name
                    it was asked under; its uses are logged as that name.
  SCOTOMA_GRANT     the grant token for commands marked [grant], or the
                    approver token, which is a grant over everything

exit: 0 done, 1 failed, 2 usage; `run` exits as CMD did.
```

`sub`, `redact` and `guard` are streaming filters: output is flushed as it is
decided, and a match that straddles two reads is still a match. A secret
value is never accepted or printed as an argument, only through stdin.

## Library

```rust
let vault = scotoma::Scotoma::open(home, "my-harness")?;        // a client; holds no key
let token = vault.grant("1h,run", &["api-password"], "log in to staging")?;  // an approver decides
let vault = vault.with_grant(&token);

let command = ["curl", "-u", "admin:[scotoma:api-password]", url];  // as the model wrote it
let code = vault.run(&command, &mut out, &mut err)?;            // the value never comes here
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
- **Grants.** Storing, removing, substituting and running need a grant: a
  token for named secrets, within limits: a duration, a number of uses,
  `run` only. One use is one command or stream that substituted a value,
  however many placeholders it held. Redaction and the guard need no grant,
  so detection never lapses.
- **Asking.** A request names its secrets and gives a reason. It waits for
  an approver: the person at the unlock terminal, or any program holding the
  approver token (`scotoma pending`, `scotoma decide`; `Scotoma::pending`,
  `Scotoma::decide`). Automatic approval is such a program; scotoma holds no
  rules of its own. A caller that already holds a grant is not made to
  wait: its new grant is minted from the one it holds, bound by both.
  `decide ID no` on a live grant ends it and everything minted from it.
- **Identity.** A grant keeps the name it was asked under, and whatever is
  done with it is logged as that name, whatever the caller claims. Without
  a grant a name is only a claim.
- **The usage log** is `audit.tsv`, append-only, one line per act:
  `unix-seconds  actor  event  secret-names  grant-id  note`. A grant's life
  reads `request` (note: the limits and the reason), then `grant` or
  `refuse` (actor: who decided; note: the grant it was minted from) or
  `abandon`, and perhaps `revoke`. Its work reads `set`, `remove`, `use` (a
  placeholder was replaced by a value), `redact` (a value was rewritten) and
  `leak` (a guard refused content). The log holds names and identifiers,
  never a value or a token.
- **The placeholder is the name.** `[scotoma:NAME]` stands for the secret's
  current value; whether it fills in is the grant's decision alone. The same
  text is what redaction writes, so a model reads back what it wrote. A
  placeholder for a secret that does not exist is left as it is.
- **Matching is exact**, leftmost-longest. Redaction and the guard also match
  a value as it reads inside a JSON string, so a serialized request body can
  be checked.
- **A use is authorized and logged before its bytes are released.** If the
  log cannot be written, nothing is substituted and no output is passed on.

## What it does not do

- **Exact matches only.** A value that comes back transformed is not caught:
  base64 (`curl -v` prints a Basic-auth header that way), hex, URL-encoding,
  or one character per line.
- **A `run`-only grant is not a wall.** It refuses to hand over the value,
  but the command it runs holds the value and can write it to a file or
  print it encoded. It stops an agent from reading a secret by asking, not
  one that is trying.
- **It is not a sandbox.** To a process running as you, the vault files are
  ciphertext, and the socket does nothing with a secret without a grant. But
  it can attach a debugger to the resident process, or read a token from the
  environment or terminal of whatever holds one, the approver token included. A grant is a bearer token: guard it like a password
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
