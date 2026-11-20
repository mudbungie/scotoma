# scotoma: design

A living document. When the code and this file disagree, one of them is a bug;
fix whichever is wrong.

## The problem

An agent needs credentials to do real work, and everything an agent reads is
sent to an inference server and written to transcripts. The goal: an agent can
**use** a secret without the value ever entering its context, the value is
unreadable at rest, and nothing uses it without the user's say-so.

## The model

- A **secret** is a named value. The name is public; the value is not.
- A **handle** is a random UUID that stands for a secret. It is safe to show
  a model, and it is the only thing the model is ever given.
- A **grant** is the user's permission: these secrets, until this time. Its
  holder presents a token.
- The **resident process** is the only thing that ever holds a value. The
  user unlocks the vault into it with a password; it dies with the session.
- The **usage log** records every act.

Four verbs, all performed by the resident process on a client's request:

- **Issue** a handle for a secret (needs a grant).
- **Substitute**: replace each handle with its secret's value, as late as
  possible on the way to execution (needs a grant). Best done as **run**:
  the resident process executes the command itself.
- **Redact**: replace each secret value in what a tool printed, before it is
  stored or shown.
- **Guard**: refuse content that holds a secret value, on its way to the
  model. A hit is an error and the request is not sent.

Redaction keeps the transcript clean; the guard is the last gate. They do not
replace each other: with only a guard, one echoed secret in the transcript
fails every later request; with only redaction, a path nobody thought to
redact leaks silently.

## Decisions

**Symmetric cryptography only.** Each secret file is sealed with
XChaCha20-Poly1305 under a random 256-bit vault key, with the secret's name
as associated data (a file copied over another secret does not open). The
vault key is sealed under an Argon2id stretch of the password, so changing
the password would rewrap one key. A quantum computer breaks public-key
schemes and only halves a symmetric key's strength; with no public key in the
design, 256-bit symmetric encryption is the post-quantum choice. A
post-quantum public-key scheme would be needed only to encrypt *to* a locked
vault, which nothing does.

**The key lives in one process.** `unlock` is that process. Everything else
is a client over a Unix socket in the vault directory, including the library:
`client.rs` cannot read a secret because it never has the key. `lock` removes
the socket's name before it answers, so a caller that hears "locked" is
right.

**Authorization is asked where the agent cannot type.** A grant is minted
only by a `y` on the resident process's own console: the terminal the user
unlocked in. That is an authorization step with no second password, and no
client call can answer it. The console is one seat today; a remote approver
(a GUI, a parent agent) is another reader of the same question later.

**One grant record; the models are ways of minting it.** A grant is
`{id, names, expires}` held in memory. Duration grants are built. A counted
grant adds a use count; a subagent grant is minted from a parent grant, never
wider or longer, and dies with it. Neither needs a second mechanism.

**A grant has a public id and a private token.** The log and the console
show the id; only the holder knows the token.

**Detection needs no grant.** Redaction and the guard reveal only whether a
string is a secret, and must keep working when every grant has expired.

**Both ways to execute.** `run`: the resident process spawns the command in
the caller's directory and environment, so the value never crosses the
socket. `substitute`: the caller gets the text and executes it, for a harness
that must own the process. `run` is the default; `substitute` is the wider
door.

**Output gets the handle back.** In `run`, a value that went in through a
handle is redacted to that same handle, so the model reads back what it
wrote. Any other secret is redacted to `[scotoma:NAME]`.

**One matcher.** Substitution, redaction and the guard are the same
streaming matcher (`src/table.rs`) over two tables: handle → value, and value
→ marker. The guard is the redactor with a match turned into an error.
Matching is exact, leftmost-longest, on bytes; the table is a sorted array
walked as a trie.

**The detector is one function.** What counts as "a secret on its way out" is
the table built by `Vault::values`: today each value exactly, raw and as a
JSON string. Catching partial or transformed values (base64, hex, a long
enough fragment) means adding entries to that table, or replacing the matcher
behind the same flow; no caller changes.

**Streams hold back only what is undecided.** A chunk boundary can fall
inside a match. Bytes that could still begin an entry are held until the next
chunk or the end; everything else is released at once.

**Handles are not stored; they are read out of the log.** A handle is valid
because its `issue` line exists. There is no handle table to drift, and a
handle survives the resident process being locked and unlocked. A handle
follows the name, not the value: rotating a secret keeps its handles working;
removing it kills them.

**Authorize, log, then release.** Each match is checked against the grant
and written to the log before its bytes are returned. If either fails,
nothing comes out, and that includes a command's output.

**Names are a conservative alphabet** (`A-Z a-z 0-9 . _ -`, no leading dot,
at most 128). A name is a file name and a log field, so neither needs
escaping and the log parses by splitting on tabs.

**Dependencies are cryptography and nothing else.** Randomness is
`/dev/urandom`; the log is TSV; the socket protocol is length-prefixed frames
written by hand.

**The command is a client of the library.** `src/bin/scotoma/` uses only the
public API, which is the test that the API is sufficient.

## What this does not solve

- **Transformed values.** Detection is exact. Base64, hex, URL-encoding,
  reversal, or printing a value one character at a time all pass. Scotoma
  stops accidents and casual exposure, not a model that is trying.
- **A hostile process running as the user.** The files are ciphertext to it, and
  the socket releases no value without a grant. It can store, replace, remove
  and list secrets (those need no grant), attach a debugger to the resident
  process, or lift a grant token from the environment of a process that holds
  one. Closing that needs the resident process under another user, or
  hardening that needs `unsafe`.
- **The wider door.** A holder of a grant can call `substitute` and read the
  value. A grant authorizes use, and use by a caller that wants to look is
  seeing. Restricting a grant to `run` only is a natural next limit.
- **Process arguments.** A substituted argument is visible in the process
  table while the command runs.
- **Memory.** Keys and values are ordinary buffers; they are not zeroed.
- **A dead caller's command** is stopped only when it next writes output.
- **Log growth.** Substitution reads the whole log to find issued handles.
  Nothing rotates it.
- **No password change, no recovery.**

## Integrating a harness

The contract, for any agent loop:

1. **The user unlocks** the vault and, when the harness asks, approves a
   grant. The harness keeps the token (`Scotoma::with_grant`).
2. **A `scotoma` tool** takes `{"name": "..."}` and returns
   `Scotoma::issue(name)`. The model then writes the handle into a later tool
   call of the same turn, for example a shell command.
3. **Execute through `Scotoma::run`** where the tool is a command: the call
   is recorded and approved in its handle form, and the output comes back
   with the handle in place. Where the harness must spawn the process itself,
   `substitute` each string of the input immediately before the spawn, never
   over serialized JSON (a value containing a quote would corrupt it), and
   `redact` what comes back before it is bounded, recorded or returned.
4. **Guard the outgoing request** at the one place it is serialized:
   `Scotoma::check(body)`, and do not send on `Error::Leak`. The guard matches
   a value as it reads inside a JSON string, so the serialized body can be
   checked as bytes.

A hit at step 4 means a seam is missing at step 3.

A harness that executes on another machine needs the resident process there:
the value should be substituted where the command runs, not carried to it.
