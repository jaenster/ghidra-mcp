# ghidra-mcp — issues to fix

Rough edges hit in real use, each with the symptom it produced. Written down so they get fixed
rather than re-discovered. The two at the top are the ones that cost the most time.

---

## Progress

Worked top to bottom, one commit per item.

**A. Repo-first session model (issue 1 + drop the short-lived local-import path)**
- [x] A1 `GHIDRA_SERVER_REPO` default repo; bare `program=` paths resolve against it
- [x] A2 remove loose-binary sessions (throwaway per-session project); `.gpr` and `ghidra://` remain
- [x] A3 local path gives the real reason, naming the host the worker is connected to
- [x] A4 `list_repos` / `list_programs` work with no session

**B. Getting binaries in (issue 2)**
- [x] B1 `import_program` — URL or uploaded bytes → repo path
- [x] B2 batch form (many files / directory + path template)
- [x] B3 analysis startable + pollable, not held open on one request
- [x] B4 `delete_program` / `move_program`

**C. Name resolution (issue 3)**
- [x] C1 accept fully namespaced names wherever names are accepted
- [x] C2 mid-function address resolves the containing function

**D. Prototypes (issue 4)**
- [ ] D1 never silently reset the calling convention
- [ ] D2 accept the convention (in the signature and as its own argument)

**E. Types (issue 5)**
- [ ] E1 `update_structure` bitfield members

**F. Smaller ones (issue 6)**
- [ ] F1 `list_data_symbols` honours `dataType`
- [ ] F2 `get_data_at_address` reports overlapping labels
- [ ] F3 `get_symbol_after` deduplicates one-address aliases
- [ ] F4 `search type=decompiled` indexes local names / field-extract syntax
- [ ] F5 `list_symbols type=LOCAL_VAR` returns function-scoped locals
- [ ] F6 `get_function_info` stack-slot types agree with `decompile`
- [ ] F7 `find_functions_matching` pages instead of blowing the token limit
- [ ] F8 `delete_namespace` removes the empty shell

**G. Sessions (issue 7)**
- [x] G1 `close_session` reports refcount vs. actual close, and takes `force`

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
