# ghidra-mcp — issues to fix

Rough edges hit in real use, each with the symptom it produced. Written down so they get fixed
rather than re-discovered. The two at the top are the ones that cost the most time.

---

## Progress

Worked top to bottom, one commit per item.

**A. Repo-first session model (issue 1 + drop the short-lived local-import path)**
- [x] A1 programs are named repository-first (`Diablo2Lod/windows/1.09d/D2Game.dll`), the same form the listings print; a path naming no repo is matched across all of them and accepted when unique. No hidden default repo — `create_repo`/`delete_repo` and all-repo `list_programs` make every repository first-class instead.
- [x] A2 loose-binary sessions removed outright — a session opens a repo program or a local `.gpr`; the import path into a per-session project is gone from the worker too
- [x] A3 local path gives the real reason, naming the host the worker is connected to
- [x] A4 `list_repos` / `list_programs` work with no session

**B. Getting binaries in (issue 2)**
- [x] B1 `import_program` — URL or uploaded bytes → repo path
- [x] B2 batch form (many files / directory + path template)
- [x] B3 analysis startable + pollable, not held open on one request
- [x] B4 `delete_program` / `move_program`

**C. Name resolution (issue 3)**
- [x] C1 accept fully namespaced names wherever names are accepted — `decompile` already did; AnalysisOps and SymbolOps each held a stale copy of the old lookup, so `get_pcode`/`get_stack_frame`/tags/attributes did not
- [x] C2 mid-function address resolves the containing function

**D. Prototypes (issue 4)**
- [x] D1 never silently reset the calling convention (already on main: preserveCallingConvention + custom-storage guard)
- [x] D2 accept the convention (in the signature and as its own argument)

**E. Types (issue 5)**
- [x] E1 `update_structure` bitfield members

**F. Smaller ones (issue 6)**
- [x] F1 `list_data_symbols` honours `dataType` — already correct on main, wired end to end; schema wording clarified
- [x] F2 `get_data_at_address` reports overlapping labels (already on main) and now the containing struct + field for an address inside one
- [x] F3 `get_symbol_after` deduplicates one-address aliases
- [x] F4 `search type=decompiled` — the raw C it matches does contain local names and `._N_M_`; the cause was the invisible 200-function cap, now reported (`coverageNote`) and raisable (`maxFunctions`)
- [x] F5 `list_symbols type=LOCAL_VAR` returns function-scoped locals
- [x] F6 `get_function_info` stack-slot types agree with `decompile`
- [x] F7 `find_functions_matching` pages instead of blowing the token limit
- [x] F8 `delete_namespace` removes the empty shell

**G. Sessions (issue 7)**
- [x] G1 `close_session` reports refcount vs. actual close, and takes `force`

**Verified** by driving a real worker against the test fixtures: C1, C2, D2, E1, F4, F5, F7,
G1, and the local-path errors. The full e2e suite passes (55/55; the 3 auth-suite failures
predate this work and reproduce on a clean tree).

**Verified against the live Ghidra Server** (ghidra.typeguru.nl): `list_repos`,
`list_programs` (all repos and per repo), `create_repo`, `import_program` by URL with analysis
— it lands as version 1, released not checked out — `create_session` on a repo path *and* on a
freshly imported program, `list_functions`, `close_session`, `delete_program` (with `force`
for a checkout left by a dead worker). No residue left behind.

`move_program` and `delete_program` now work without `force`, including straight after a
session has had the program open. Two causes: the rename path took a checkout first, which is
exactly what Ghidra refuses to rename over; and the repo worker held its project (and so the
files it imported) forever, which is now let go of after every job. `force` remains for a
checkout a dead worker left behind.

`delete_repo` was removed — Ghidra Server does not implement deleting a repository at all.

**Verified end to end against the live server:** request_upload → PUT → import_program
uploadId → create_session → list_functions → close_session → move_program → delete_program,
leaving nothing behind. A `ghidra://` URL naming a different host is refused.

The e2e fixtures are now pre-analysed `.gpr` projects (`npm run fixtures:ghidra`), since a
session can no longer open a loose binary. They run serially: the suites share those
projects and Ghidra locks a project exclusively.

---

## 1. Session creation should not need a `ghidra://` URL

**Today**

```
create_session binaryPath="ghidra://ghidra.typeguru.nl:13100/Diablo2Lod/windows/1.09d/D2Game.dll"
```

Nothing discoverable says that is the form. It has to be told, once, by somebody who already knows.

**What goes wrong without it**

A local project path is always rejected as *"Binary not found"*:

```
create_session binaryPath="~/code/ghidra/Diablo2Lod.gpr"   -> Binary not found
```

The file is right there. The reason it fails is that the worker is remote and cannot see this
machine's disk — but the error blames the file, which sends you hunting through every `.rep` on the
box for a corrupt project. That is the single most expensive papercut in the list.

**Asking for**

- A configured default server and repo, so a session opens on a plain program path:
  ```
  create_session program="/windows/1.09d/D2Game.dll"
  ```
  and, when the repo is unambiguous or configured, on a bare name:
  ```
  create_session program="1.09d/D2Game.dll"
  ```
- The `ghidra://…` form still accepted, for pointing at a different server.
- The port optional (it already is — `ghidra://host/Repo/path` fills in `:13100`; that is also
  undocumented).
- **A local path should fail with the real reason**: "this worker runs on <host> and cannot read
  your local filesystem; use a server path" — naming the host it IS connected to.

**Discovery, which is the other half of the same problem**

`list_programs` and `list_repos` both need a session, and a session needs a program path. So there
is no way to see what is on the server before you have already guessed something correctly.

- `list_repos` should work with no session.
- `list_programs` should take a repo and work with no session.

---

## 2. There is no way to add a file

Everything can be read and edited; nothing can be imported. Right now a new binary means opening the
Ghidra GUI by hand, which breaks every automated flow and means an agent cannot prepare its own
material.

Concretely: there are **899 binaries** sitting in
`/Users/jaenster/code/tmp/ghidra-d2-frontend` — every published Diablo II patch, one directory per
installer — and none of them can be got onto the server through the MCP.

**Asking for**

```
import_program
  file:        local path, or bytes, or a URL the worker can fetch
  programPath: "/windows/1.09d/Game.exe"      where it lands in the repo
  processor:   optional, e.g. "x86:LE:32:default"   (usually auto-detected)
  analyze:     bool, default true
  overwrite:   bool, default false
```

Returning the `programPath` and whether analysis finished. Notes from the use case:

- **It must be able to take many.** Importing four modules for each of six eras is 24 calls; a
  batch form, or a directory + a path template, would matter.
- **Analysis is the slow part.** It should be startable and pollable rather than held open on one
  request — the D2R open already times out today (see below), and a fresh import is worse.
- **Uploading from the client matters.** The worker cannot see this machine's disk (issue 1), so
  either the bytes go over the wire or the worker fetches a URL. A URL is enough for our case:
  everything is on `https://files.typeguru.nl/diablo/patch files/`.
- `delete_program` and `move_program` for the same reason — an import that landed in the wrong place
  currently needs the GUI.

---

## 3. Name resolution does not accept its own output

`list_symbols` and `list_data_symbols` emit fully namespaced names. `decompile` will not take them:

```
decompile name="Storm::Source::SFile::SFILE_EnqueueAsyncRequest"   -> Function not found
decompile address="0x..."                                          -> works
```

Anything a tool prints should be accepted by the tool that consumes it.

Related: `decompile` at a **mid-function address** also errors "Function not found" rather than
resolving the containing function. It should either resolve it or say "0x… is inside <name>, whose
entry is 0x…".

---

## 4. `set_prototype` destroys the calling convention

Two separate faults, both serious on 32-bit code.

**It resets the convention to default.** Applying a plain C signature discards Ghidra's
auto-detected register parameter storage, so `__usercall`/`__fastcall` functions decompile wrongly
afterwards — the real parameters vanish and the body reads as nonsense. On a binary full of
register-convention functions this is a data-loss bug, not a papercut.

**It cannot be told the convention either.** Passing one is parsed as part of the return type:

```
set_prototype "ushort __stdcall Foo(uint a)"
  -> Can't resolve return type: ushort __stdcall
```

Dropping the keyword works and records nothing. Either accept it in the signature, or take
`callingConvention` as its own argument — and never silently reset it.

---

## 5. `update_structure` cannot express bitfields

`int:1` members are silently scattered into separate bytes, corrupting the layout. Observed while
refining flag bytes; had to be reverted with `undo`.

Workaround in use is a named `undefined1` with the bit meanings in a comment, so `field & mask` at
least compiles. Real 1-bit members need the Ghidra DataTypeManager bitfield API.

---

## 6. Smaller ones, still real

- **`list_data_symbols` ignores its `dataType` filter** — returns every global regardless.
- **`get_data_at_address` hides overlapping labels.** At an address covered by a struct-typed
  symbol it reports only the struct, while `get_symbol_after` does list the children. Two tools,
  two answers, same address.
- **`get_symbol_after` returns duplicates** for MSVC RTTI descriptors — the `struct_X_RTTI_*` label
  and the namespaced `X::RTTI_*` at one address.
- **`search type=decompiled` does not index local names** or field-extract syntax (`._N_M_`), so
  those queries return 0 and look like "not present" rather than "not indexed".
- **`list_symbols type=LOCAL_VAR` returns nothing** for function-scoped locals.
- **`get_function_info` shows raw stack-slot types** (`undefined1[N]`) where `decompile` resolves
  the real struct. Always cross-check; better, make them agree.
- **`find_functions_matching` can blow the token limit** on broad queries with no way to page it.
- **No `delete_namespace`.** After moving every symbol out, the empty shell remains and downstream
  generators emit an empty file for it.
- **Duplicate function names exist** in real projects (two `NET_D2GS_SERVER_Send_0x26_Chat`), so
  name-addressed tools are ambiguous by nature — another reason address-addressing must always work.

---

## 7. Sessions can outlive `close_session`

Closing a session that another client also has open reports success and leaves it running;
`list_sessions` shows it again immediately. It took a second close per session to actually clear
them.

Either `close_session` should say it decremented a refcount rather than closed, or take a `force`.
`list_sessions` showing `clientCount` helps, but only if the close result mentions it.

# Round three — a 516-binary import (2026-08-24)

Importing every Windows D2 binary for every version: 516 PEs across 36 version folders, seven jobs,
`analyze: false`. It worked, and nothing failed. What follows is what got in the way.

## 13. `import_status` is unusable on a job of any size

Issue 9 said the "Library not found" blocks bury the useful line. At 80 items per job they do not
just bury it — they make the tool unanswerable:

```
import_status jobId=0be5ecf6
  -> result (62,408 characters across 46 lines) exceeds maximum allowed tokens
```

That was a **40**-item job. The one line anybody wants is `done: 7 / failed: 0`, and it cannot be
read without spooling 62 KB to a file and grepping it. For an MCP tool this is a hard failure, not
a verbosity complaint: the polling call for a long-running job must always fit in a response.

**Asking for**

- `import_status` returns the summary only by default — `state`, `total`, `done`, `failed`,
  `current`, and the failed items' paths and reasons.
- The per-item import log behind a flag (`verbose: true`), or addressable per item
  (`import_status jobId=… programPath=…`).
- Failures are what matter; successes need one line each at most.

## 14. "checked out" gives no way to find out by whom, and `force` is not the answer

Moving a program that is checked out fails with:

```
move_program /windows/1.14d/CheckRevision.dll -> Error: CheckRevision.dll is checked out
```

`force` is documented as "break a checkout left behind by a dead worker, losing anything
uncommitted in it". That framing suggests a stale-lock cleanup, so it looks like the obvious fix.
It is not. The checkout here belonged to a live GUI:

```
move_program force=true -> Error: Undo-checkout not permitted, checkout was made by jaenster
```

— which is the *right* refusal, but it only appears after you have already asked for the
destructive option. And the program genuinely had unsaved work: opening a session and committing it
first produced **version 3**, so a `force` that had succeeded would have thrown that away.

**Asking for**

- The error names the holder and the age: "checked out by jaenster since 2026-08-23T14:02Z".
- A read-only way to ask before acting — `list_programs` gaining `checkedOut` / `checkedOutBy`, or a
  `checkout_status` call. Right now the only way to discover a checkout is to attempt a mutation.
- `force`'s description should say it refuses another user's checkout, so it is not read as the
  generic unstick.

## 15. Batch import cross-links only within the job

Auto-linking works and is genuinely useful, but it only sees what is already in the repository:

```
[D2CMP.DLL]  -> [/windows/classic/1.05/D2CMP.dll] (previously imported)
[D2LANG.DLL] -> not found in project
```

Both are in the same job; `D2CMP` resolved because it happened to be imported earlier in the item
list, `D2Lang` did not because it comes later alphabetically. So the link graph a version ends up
with depends on the order items were passed, which is arbitrary. A second linking pass at the end
of a job — or ordering by dependency — would make it deterministic.

## 16. There is no way to ask what a program's source bytes were

`get_program_info` reports the original import path (`/D:/___D2_REVERSE/1.14d/Game.exe`) but no hash
of the loaded binary. `create_session` returns a `binaryHash`, but it does not match the SHA-256 of
either candidate file on disk, so it appears to be over the Ghidra program rather than the PE. With
36 versions of the same twenty DLL names in one repository, "which build is this actually" is a
question that now gets asked constantly, and there is no way to answer it from the API.

Exposing the imported file's MD5/SHA-256 — Ghidra already records it, the import log prints
`?MD5=…` — would settle it.

## 17. `move_program` reports "target exists" before it reports "checked out"

Two blockers can stop a move, and the order they are checked in hides the one that matters:

```
move_program /windows/1.06b/Fog.dll -> /windows/classic/1.06b/Fog.dll
  -> Error: Target already exists: /windows/classic/1.06b/Fog.dll

move_program /windows/1.06b/Fog.dll -> /windows/_duplicates/classic/1.06b/Fog.dll
  -> Error: Fog.dll is checked out
```

Same source file, one second apart. The first error is true but not the whole truth, and it is the
one you get when moving to the place you actually want it. Acting on it — clearing the target,
renaming things out of the way — is wasted work, because the move was never going to succeed.

During a 90-program reorganisation this produced a wrong diagnosis: a batch that failed with
"target exists" looked like the checkouts had been released, when nothing had changed.

**Asking for:** validate the source first (it is the cheaper check and the harder blocker), or
report all blocking conditions at once — "checked out by jaenster; target also exists".

## 18. Nothing can release a checkout

Once a checkout exists there is no way through the MCP to clear it:

- `close_session` (with `force`) does not release it — the checkout outlives the session.
- `commit` explicitly keeps it ("keeping the checkout so editing can continue").
- `move_program force=true` refuses another user's, which is correct but leaves no path forward.
- Closing the repository-level session and retrying changes nothing.

So a checkout made once — by a GUI, or by a worker that died months ago — permanently pins that
program's path until a human opens the Ghidra GUI and undoes it. For an agent doing bulk work that
is a hard stop, and it is invisible up front (issue 14: there is no way to list checkouts).

**Asking for:** an `undo_checkout` / `checkin` that can release a checkout the caller's own account
holds, and `list_programs` surfacing `checkedOut` so a plan can route around them before starting.
