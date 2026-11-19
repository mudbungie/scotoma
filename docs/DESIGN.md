# scotoma: design

A living document. When the code and this file disagree, one of them is a bug;
fix whichever is wrong.

## The problem

An agent needs credentials to do real work, and everything an agent reads is
sent to an inference server and written to transcripts. The goal: an agent can
**use** a secret without the value ever entering its context.

## The model

Three nouns, two verbs.

- A **secret** is a named value. The name is public; the value is not.
- A **handle** is a random UUID that stands for a secret. It is safe to show
  a model. It is the only thing the model is ever given.
- The **usage log** records every act on a secret.

- **Substitute**: replace each handle with its secret's value. Done by the
  harness, on the way *to* execution, as late as possible.
- **Redact**: replace each secret value with `[scotoma:NAME]`. Done by the
  harness to what a tool printed, before it is stored or shown.
- **Guard**: refuse content that holds a secret value. Done by the harness to
  everything on its way to the model. A hit is an error and the request is
  not sent.

Redaction keeps the transcript clean; the guard is the last gate. They do not
replace each other: with only a guard, one echoed secret in the transcript
fails every later request; with only redaction, a path nobody thought to
redact leaks silently.

## Decisions

**One mechanism.** Substitution, redaction and the guard are the same
streaming matcher (`src/table.rs`) over two tables: handle → value, and value
→ marker. The guard is the redactor with a match turned into an error.

**The detector is one function.** What counts as "a secret on its way out" is
the table built by `Scotoma::values`: today each value exactly, raw and as a
JSON string. Catching partial or transformed values (base64, hex, a long
enough fragment) means adding entries to that table, or replacing the matcher
behind the same `Stream`; no caller changes.

**Exact, leftmost-longest matching, on bytes.** No escape syntax, no
delimiters: the handle is 122 random bits, so the bare string is unambiguous
wherever it appears. The table is a sorted array walked as a trie, so a
position that begins no entry costs two binary searches.

**Streams hold back only what is undecided.** A chunk boundary can fall
inside a match. Bytes that could still begin an entry are held until the next
chunk or the end; everything else is released at once.

**Handles are not stored; they are read out of the log.** A handle is valid
because its `issue` line exists. There is no handle table to drift from the
log, and no in-memory state, so the process that issues a handle and the
process that substitutes it need share only the vault directory. Agent
harnesses run tools in separate processes and resume interrupted turns in new
ones; a handle table in memory would not survive either.

**A handle follows the name, not the value.** Rotating a secret keeps its
handles working; removing it kills them.

**Log before release.** A substitution is written to the log before its bytes
are returned. An unwritable log means no secret leaves.

**Names are a conservative alphabet** (`A-Z a-z 0-9 . _ -`, no leading dot,
at most 128). A name is a file name and a log field, so neither needs
escaping and the log parses by splitting on tabs.

**No dependencies.** Randomness is `/dev/urandom`; the log is TSV, not JSON.

**The command is a client of the library.** `src/bin/scotoma/` uses only the
public API, which is the test that the API is sufficient.

## What this does not solve

- **Transformed values.** Detection is exact. Base64, hex, URL-encoding,
  reversal, or printing a value one character at a time all pass. Scotoma
  stops accidents and casual exposure, not a model that is trying.
- **Local readers.** The vault is plain files, mode 0600. Anything running as
  the same user can read it. See "Next: the locked vault".
- **Process arguments.** A substituted argument is visible in the process
  table while the command runs.
- **Memory.** Values are ordinary strings; they are not zeroed after use.
- **Log growth.** Substitution reads the whole log to find issued handles.
  Nothing rotates it.

## Integrating a harness

The contract, for any agent loop:

1. **A `scotoma` tool** takes `{"name": "..."}` and returns
   `Scotoma::issue(name)`. The result is the handle. The model then writes the
   handle into a later tool call of the same turn, for example a shell command.
2. **Substitute at the executor**, after the tool call's input has been
   recorded and approved in its handle form, and immediately before it reaches
   the process that runs it. Substitute inside each string of the input, not
   over serialized JSON: a value containing a quote would corrupt the
   document.
3. **Redact tool output** before it is bounded, recorded, or returned as a
   tool result. Output that the model can page through later counts.
4. **Guard the outgoing request** at the one place it is serialized:
   `Scotoma::check(body)`, and do not send on `Error::Leak`. The guard matches
   a value as it reads inside a JSON string, so the serialized body can be
   checked as bytes.

Steps 3 and 4 overlap on purpose: 3 keeps secrets out of what is stored, 4 is
the last gate before the network, and a hit at 4 means a seam is missing at 3.

Open question for a harness that executes on another machine: substituting
before the hop sends the value over that transport; substituting after needs
a vault on the executing machine.

## Next: the locked vault

Not built. This section is the design to attack before it is.

**The gap.** Today any process running as the user can read `secrets/`. The
requirement: values are durable, unreadable at rest, and released only by
scotoma, only under an authorization the user gave.

**At rest.** Each secret file is ciphertext under a random 256-bit vault key
(an authenticated cipher, XChaCha20-Poly1305). The vault key is itself stored
encrypted under a key stretched from the user's password (Argon2id). Changing
the password rewraps one key, not every secret.

*Post-quantum:* a quantum computer breaks public-key schemes; against a
256-bit symmetric cipher it only halves the exponent, leaving 128-bit
strength. A password-unlocked vault has no public key in it, so this design is
already quantum-resistant. A post-quantum public-key scheme (ML-KEM) earns its
place only if something must be encrypted *to* a locked vault, such as storing
a new secret without unlocking.

**The resident process.** `scotoma unlock` reads the password from the
terminal and starts one long-lived process that holds the vault key in memory
and listens on a private socket. Nothing else ever has the key; it is gone at
`scotoma lock`, logout or reboot. Every other scotoma invocation, and the
library, becomes a client of that process.

**Authorization is a grant.** The resident process releases a value only
against a *grant*: a record it holds in memory of who may use which secrets,
until when, and how many more times. A grant is identified by a random token
that the user hands to whatever they are authorizing.

- *Duration* (the first one to build): `scotoma grant --for 1h [NAME...]`,
  run by the user, prints a token the harness is started with.
- *Counted*: the same grant with a use count; one-time is a count of one.
- *Subagent*: a grant minted from a parent grant, never wider or longer than
  its parent, revoked with it.

One record, three limits (names, expiry, uses); the other models are ways of
minting it, not new mechanisms. Every `issue` and `use` log line gains the
grant that allowed it.

**What needs a grant.** Issuing a handle and substituting do. Redaction and
the guard do not: they reveal only that a given string *is* a secret, and they
must keep working after a grant expires or leaks would resume.

**What this still does not stop.** A process running as the same user can
attach a debugger to the resident process, or read the token out of the
harness's environment. Closing that needs the resident process to run as a
different user, or OS hardening that needs `unsafe`. Encryption at rest and
grants stop a process that merely reads files or guesses at the socket.

**Costs.** Two cryptography dependencies (a password hash and a cipher); the
no-dependency rule becomes "no dependency that is not cryptography we must
not write ourselves". The library stops being usable without a running
resident process.

**Open decisions.**

1. Is 256-bit symmetric encryption the post-quantum requirement, or is a
   public-key path into a locked vault wanted (then ML-KEM)?
2. Does the client receive the substituted text and execute it, or does the
   resident process execute the command itself so the value never crosses the
   socket? The second is tighter and makes the resident process the parent of
   every command.
3. Does minting a grant ask for the password again, or is being at the
   terminal that ran `unlock` enough?
