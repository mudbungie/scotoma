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
- A **placeholder**, `[scotoma:NAME]`, stands for a secret. It is what a
  model writes to use one and what it reads where the value was.
- A **grant** is the user's permission: these secrets, until this time. Its
  holder presents a token.
- The **resident process** is the only thing that ever holds a value. The
  user unlocks the vault into it with a password; it dies with the session.
- The **usage log** records every act.

Three verbs, all performed by the resident process on a client's request:

- **Substitute**: replace each placeholder with its secret's value, as late as
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

**One seat decides, and policy sits in it, not here.** A grant request waits
at the desk (`src/desk.rs`) until an approver answers. The approver is
whoever holds the approver token, shown once on the console at unlock: the
person typing `y` there, a GUI, or a program that approves by rule. Scotoma
has no rules of its own; automatic approval is an approver that says yes,
and the log names it. A console that is closed is not a refusal, so a
headless resident process is served by its approvers.

**The approver token is a grant.** It is the root: over every secret, without
limits. Every other grant descends from it, so "who authorized this" is
always a grant, and there is one check. Storing and removing a secret need a
grant over its name like any other act.

**One grant record; the models are its limits.** A grant is
`{id, actor, names, expires, uses left, run only, parent}` held in memory,
asked for as comma-joined limits (`1h`, `3x`, `run`). An absent limit is the
largest number, so there is no "unlimited" case.

**A request says why.** The reason is shown to whoever decides and written to
the log with the limits. Control characters are removed before either.

**A grant fixes who its holder is.** The name a grant was asked under is the
name its uses are logged as, whatever the caller claims later. A grant minted
from a grant is named by the parent that asked. Without a grant, a name is a
claim.

**A request ends one of four ways, each logged:** granted, refused,
abandoned (the caller hung up, or the vault locked), or the log could not be
written, which is a refusal. Nothing waits forever on a caller that left.

**A no to a live grant ends it.** `decide ID no` answers an open request or
revokes a grant; a revoked grant has no uses left, and since every question
is asked up the chain, neither has anything minted from it.

**A use is a flow that substituted a value.** One command or one stream,
however many placeholders it held; a flow that matched nothing or was refused
costs nothing. The grant is
charged before the first value is released.

**A grant minted from a grant is the intersection.** Every question (covers
this name? still live? may be handed a value? one use left?) is asked of the
grant and then of its parent. So a child is never checked for being "no
wider" when minted: it simply cannot do what its parent cannot, and it dies
when its parent expires or is spent. A child's use is charged to every
ancestor.

**The token presented is who authorizes.** A grant request with no token
waits for an approver; with a token, it is answered by that grant at once.
One request, no second verb. To ask for more, ask without a token.

**A grant has a public id and a private token.** The log and the console
show the id; only the holder knows the token.

**Detection needs no grant.** Redaction and the guard reveal only whether a
string is a secret, and must keep working when every grant has expired.

**The caller's connection is the command's lifeline.** In `run`, the caller's
input is relayed to the command, and the command's group is killed when the
connection closes. There is no timeout and no cancel request: whoever wants a
limit stops waiting, which is the one signal a crashed caller also gives.

**Both ways to execute.** `run`: the resident process spawns the command in
the caller's directory and environment, so the value never crosses the
socket. `substitute`: the caller gets the text and executes it, for a harness
that must own the process. `run` is the default; `substitute` is the wider
door.

**The placeholder is the name, in both directions.** There is no handle to
issue, store or look up: the model writes `[scotoma:NAME]`, the grant decides
whether it fills in, and redaction writes the same text where the value was,
so the model reads back what it wrote. An earlier design issued a random UUID
per secret; it bought nothing the grant does not already decide, and cost a
tool call and a table.

**One matcher.** Substitution, redaction and the guard are the same
streaming matcher (`src/table.rs`) over two tables: placeholder → value, and
value → placeholder. The guard is the redactor with a match turned into an error.
Matching is exact, leftmost-longest, on bytes; the table is a sorted array
walked as a trie.

**The detector is one function.** What counts as "a secret on its way out" is
`forms::of` (`src/forms.rs`): each value as stored, inside a JSON string,
percent-encoded, and base64 at each of the three alignments it can take inside
a longer run. Every form is a fixed byte string, so detection stays one linear
pass whatever is added. A base64 form is the characters the value alone
decides, and is dropped under eight characters, where it would match by
chance. Substring or fuzzy matching would replace the matcher behind the same
flow; no caller changes.

**Streams hold back only what is undecided.** A chunk boundary can fall
inside a match. Bytes that could still begin an entry are held until the next
chunk or the end; everything else is released at once.

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

- **Transformed values.** Detection knows a fixed set of forms. Hex, a
  second layer of encoding, reversal, a fragment, or printing a value one
  character at a time all pass. Scotoma
  stops accidents and casual exposure, not a model that is trying.
- **A hostile process running as the user.** The files are ciphertext to it, and
  the socket does nothing with a secret without a grant. It can attach a
  debugger to the resident process, or lift a token, the approver's included,
  from the environment or terminal of a process that holds one. Closing that needs the resident process under another user, or
  hardening that needs `unsafe`.
- **The wider door.** A holder of a grant can call `substitute` and read the
  value, unless the grant is `run` only. Even then the command it runs holds
  the value and can write it to a file or print it encoded: `run` only stops
  asking, not trying.
- **Process arguments.** A substituted argument is visible in the process
  table while the command runs.
- **Memory.** Keys and values are ordinary buffers; they are not zeroed.
- **A command that will not read.** If a command leaves a full pipe of
  input unread, the resident process's reader waits on it and does not
  notice the caller leave until the command reads or ends.
- **Log growth.** Nothing rotates the log.
- **No password change, no recovery.**

## Integrating a harness

The contract, for any agent loop:

1. **The user unlocks** the vault. The harness asks for a grant per agent,
   under that agent's name and with its reason, and keeps the token
   (`Scotoma::with_grant`). Whatever shows the user a prompt holds the
   approver token and loops on `Scotoma::pending` / `decide`.
2. **Tell the model the names** (`Scotoma::names`) and the form
   `[scotoma:NAME]`. It writes that into a tool call, for example a shell
   command.
3. **Execute through `Scotoma::run`** where the tool is a command: the call
   is recorded and approved in its placeholder form, and the output comes
   back with the placeholder in place. Where the harness must spawn the process itself,
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
