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
  harness, on the way *to the model*: tool output, and the outgoing request.

A harness that does both at every boundary gives the model a blind spot
exactly the shape of the secret.

## Decisions

**One mechanism.** Substitution and redaction are the same streaming
find-and-replace (`src/table.rs`) over different tables: handle → value, and
value → marker. One matcher is tested once.

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

- **Transformed values.** Redaction is exact. Base64, hex, URL-encoding,
  reversal, or printing a value one character at a time all pass. Scotoma
  stops accidents and casual exposure, not a model that is trying.
- **Local readers.** The vault is plain files, mode 0600. Anything running as
  the same user can read it. Encryption at rest would need a key the same
  user also holds; it is left out until there is somewhere better to keep one.
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
4. **Redact the outgoing request** at the one place it is serialized. The
   redactor matches a value as it reads inside a JSON string, so the
   serialized body can be scanned as bytes.

Steps 3 and 4 overlap on purpose: 3 keeps secrets out of what is stored, 4 is
the last gate before the network.

Open question for a harness that executes on another machine: substituting
before the hop sends the value over that transport; substituting after needs
a vault on the executing machine.
