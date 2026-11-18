# mcp-drakkar

An MCP server exposing [Drakkar](https://github.com/sebdraven/drakkar), a static
analysis engine for Android APKs, raw DEX files and native ELF libraries, as one
tool per analysis mode: 38 tools, every parameter typed, every answer in the same
envelope.

It exists to remove three specific failure modes of running those measurements by
hand and pasting the output into a conversation:

1. **Paths with spaces, badly escaped.** The corpus lives under directories named
   `pCloud Drive` and `These`. `exec.Command` takes a `[]string`; there is no
   shell, so there is nothing to escape.
2. **Invented flags.** `--diff-json` was once proposed and does not exist. Here
   every parameter is typed and maps to an entry in a whitelist built from
   Drakkar's own clap struct: a flag that does not exist is not refused, it is
   inexpressible.
3. **`awk` over TSV columns.** Some modes have no JSON at all, so the TSV is not a
   rendering choice there — it is the only output. The parsing moves out of the
   conversation and into tested Go, once, with the header read rather than
   assumed.

## Contents

- [Install](#install)
- [Configuration](#configuration)
- [Tools](#tools)
- [The answer](#the-answer)
- [Background jobs](#background-jobs)
- [Reading a sample through its bundle](#reading-a-sample-through-its-bundle)
- [Native code](#native-code)
- [Design rules](#design-rules)
- [What is deliberately not exposed](#what-is-deliberately-not-exposed)
- [Layout and tests](#layout-and-tests)
- [Releases](#releases), [CI](#ci), [Git hooks](#git-hooks)

## Install

Each [release](https://github.com/sebdraven/mcp-drakkar/releases) carries one
bare binary per target — `mcp-drakkar-darwin-arm64`, `mcp-drakkar-linux-amd64`,
`mcp-drakkar-linux-arm64` — with nothing to unpack, each next to a
`checksums-<target>.txt` holding its whole SHA-256. Put it anywhere and declare
it to the MCP client:

```json
{
  "mcpServers": {
    "drakkar": {
      "command": "mcp-drakkar"
    }
  }
}
```

`drakkar` must be on the `PATH`. **This server never builds, installs or
downloads it.** If it is absent, the server logs it on stderr at startup,
`drakkar_version` says so, and every tool that runs Drakkar refuses with the same
message.

The binary answers for itself, since nothing travels alongside it:

```
$ mcp-drakkar -version
mcp-drakkar 0.15.0
commit:         <the full commit, injected at link time>
target:         darwin/arm64
go:             go1.27.1
drakkar tested: 0.6.0 (33d1c0e3f55df245268f084f905d5b1534c6514f)
```

`drakkar tested` is the Drakkar the tool surface was written against. Some
native modes need a newer one; each section below says which.

## Configuration

There is nothing to declare in advance. Paths are tool parameters, given per
call, the way they are in a shell, and they must be **absolute** — a relative
path would be resolved against the child's working directory, which is the
call's output directory and not your shell.

Output goes wherever the call's `out_dir` says. Three tools require it,
`drakkar_bundle`, `drakkar_dart_snapshot` and `drakkar_native_strings`, and
refuse a call without it; so does every call with `background`. For every other
call, omitted, the server makes a fresh directory under the system temp
directory and returns its path in `report_path`. That fallback exists for one
reason: Drakkar's own `--out` defaults to `./reports` *relative to the working
directory*, which for a server started by an MCP client is arbitrary. The server
never lets that default apply — it substitutes an absolute directory and says
where it is.

Optional environment variables:

| Variable | Default | |
|---|---|---|
| `DRAKKAR_TIMEOUT_FAST` | `2m` | inventories, string dumps, `drakkar_native` without `disasm` |
| `DRAKKAR_TIMEOUT_DIFF` | `10m` | the diffs, `drakkar_native` with `disasm` and the other native modes |
| `DRAKKAR_TIMEOUT_MATRIX` | `1h` | `drakkar_diff_matrix` |
| `DRAKKAR_TIMEOUT_BULK` | `1h` | a whole `directory` |
| `DRAKKAR_MAX_JOBS` | `2` | background jobs running at once |

Timeouts are Go durations (`90s`, `45m`); a call can override its own with
`timeout_seconds`. An unreadable or non-positive value falls back to the default.

## Tools

One tool per mode, not a generic "run drakkar with these arguments". A generic
tool cannot have a whitelist: an args array *is* a command line, and nothing would
then separate `--diff-ngram`, which exists, from `--diff-json`, which does not.

Most tools that analyse an APK also take `directory` to process a whole batch,
one report per sample. Every tool description carries its own caveats; this
table is the map.

**Server and legends**

| Tool | What it answers |
|---|---|
| `drakkar_version` | which Drakkar is in use, which one this server was written against, the timeouts, and where output lands by default — call it first when something refuses |
| `drakkar_legend` | Drakkar's own legend for a mode, where a metric's limits are stated: topics `manifest`, `cert`, `dating`, `assets`, `entries`, `resources`, `api_surface`, `diff_dex`, `diff_strings`, `diff_explain`, `diff_matrix`, `disasm`, `decompile`, `bundle`, `native`, `dart_snapshot`, `native_strings`; reads no sample |

**Manifest, signature, dating**

| Tool | What it answers |
|---|---|
| `drakkar_manifest` | permissions, components, intent filters, derived entry points |
| `drakkar_cert` | signature schemes v1/v2/v3/v3.1 and the X.509 certificates |
| `drakkar_dating` | raw dating indicators — no date is ever estimated |

**DEX code**

| Tool | What it answers |
|---|---|
| `drakkar_strings` | the DEX string pool, whole or filtered |
| `drakkar_disasm` | selected classes disassembled with operands resolved |
| `drakkar_decompile` | selected classes decompiled to Java by dex-decompiler, to check against `drakkar_disasm`; Drakkar 0.2.0 |
| `drakkar_dyn_entrypoints` | components reached other than by a manifest declaration |
| `drakkar_reflection_inputs` | where the name of each reflection target comes from |
| `drakkar_api_surface` | the protocol the sample declares: Retrofit verbs and routes, `@Path`/`@Query` names, Gson `@SerializedName` keys |
| `drakkar_orphan_audit` | methods unreachable from the roots, in islands, over four root stages |
| `drakkar_probe_api` | is this one API a graph node, and is it reachable, with paths |

**Bundle** — see [below](#reading-a-sample-through-its-bundle)

| Tool | What it answers |
|---|---|
| `drakkar_bundle` | everything Drakkar extracts from one sample, every class disassembled and decompiled, under `OUT/<sha256>/`; Drakkar 0.2.0 |
| `drakkar_bundle_index` | the classes of a bundle, filtered — the tool for choosing what to read |
| `drakkar_bundle_class` | one class of a bundle: whole-class Java, per-method Java, `.dasm`, per-method records |

**Comparison**

| Tool | What it answers |
|---|---|
| `drakkar_diff_dex` | same source tree? opcode fingerprints, blind to operands by design |
| `drakkar_diff_explain` | what actually differs in the operands of matched methods |
| `drakkar_diff_strings` | what differs in the string pools, where `static final` values live |
| `drakkar_diff_matrix` | all-against-all over a directory, plus single-linkage groups |

**Archive, resources, assets**

| Tool | What it answers |
|---|---|
| `drakkar_resources` | resolve, dump, cross-reference or find unreferenced resources |
| `drakkar_assets` | inventory, fingerprint or extract the `assets/` entries |
| `drakkar_list_entries` | every entry path in the archive; nothing extracted |
| `drakkar_extract_entry` | extract matching entries only — never the whole archive |
| `drakkar_extract_libs` | every native ELF, including the ones outside `lib/` |

**Native code** — see [below](#native-code)

| Tool | What it answers |
|---|---|
| `drakkar_native` | every ELF found by content, its JNI exports and tables, the binding of DEX native methods to them and, with `disasm`, the static disassembly of the JNI functions and the instructions of chosen ones — [details](#binding-and-disassembling-native-code) |
| `drakkar_native_arch` | ABI, word size and machine of each `.so` under `lib/` |
| `drakkar_native_strings` | the strings of every ELF, with how each boundary was found, cryptographic constants and Rust format arrays; on request the code forming each address and the crates — [details](#extracting-native-strings) |
| `drakkar_native_symex` | the symbolic value at watched instructions of one AArch64 function, path by path — [details](#following-a-value-through-a-native-function) |
| `drakkar_native_xrefs` | what refers to an address: its function, the branches, the instructions forming it, the data words holding it — [details](#finding-what-refers-to-a-native-address) |
| `drakkar_native_words` | 8-byte words at addresses, relocations applied, and what each designates — [details](#reading-native-data-words) |
| `drakkar_native_vtables` | the Rust method tables, found by their shape — candidates, not proofs — [details](#listing-rust-method-tables) |
| `drakkar_native_labels` | per function, its strings and a readable label: its function name (`fn_name`), else its log tag (`log_tag`), else its source path (`source_path`) — a reading aid, not a proven name — [details](#labelling-native-functions-by-their-strings) |
| `drakkar_dart_snapshot` | the Dart AOT snapshot blobs of a Flutter app's `libapp.so` — [details](#reading-a-flutter-snapshot) |

**Rules**

| Tool | What it answers |
|---|---|
| `drakkar_scan` | the MITRE ATT&CK for Mobile detections from the rule engine |

**Background jobs** — see [below](#background-jobs)

| Tool | What it answers |
|---|---|
| `drakkar_job_status` | the state of a job and, once it has ended, its envelope; by `job_id`, or by `out_dir` after a restart |
| `drakkar_job_cancel` | cancel a running job, which kills drakkar |
| `drakkar_job_list` | the jobs this server process knows of, against `DRAKKAR_MAX_JOBS` |

Two tools cover several modes — `drakkar_resources` and `drakkar_assets` — and
only because Drakkar itself dispatches each as a single branch with a single
output shape. The selector is a closed enumeration, so the whitelist still holds.
The three inventories are *not* merged despite sharing a branch upstream: their
report shapes have no field in common, and each carries a different caveat that
belongs in its own description. A description covering three semantics warns
about none of them.

## The answer

Every tool that runs Drakkar returns the same envelope:

| Field | What it holds |
|---|---|
| `drakkar` | which Drakkar, the exact argv, the exit code, the duration, whether it timed out or was cancelled, and `complete` |
| `stderr` | the whole of stderr verbatim, counts of the `[OK]`/`[FAIL]`/`[PANIC]`/`[AVERT]` markers, and the named failures |
| `result` | the scalar head of the report: the measurement itself |
| `tails` | one entry per unbounded array, each with `total`, `returned`, `truncated` and a preview |
| `rows` | for TSV-only modes: the header as read, a declared preview, and the count of malformed lines |
| `report_path` | the complete report on disk |
| `notes` | anything that changes how the numbers should be read |

The split is the volume strategy, and it follows the shape of Drakkar's own
reports: a head of scalars — the Jaccard, the counters, the threshold actually
used — and tails of arrays that grow with the corpus. The head is the number you
read; the 299 classes of a `--diff-dex` are what you open afterwards, and only
sometimes. So the head comes back inline and verbatim, each array becomes a
declared preview of `max_rows` items (50 by default, 2000 at most), and the whole
report stays where Drakkar wrote it. Nothing is ever cut without `truncated`
saying so.

`groups` and `failed` stay inline for `drakkar_diff_matrix` against that rule:
they *are* the answer rather than the appendix, and a sample that could not be
read must not be quietly absent.

**Read `stderr` and `notes` before the numbers.** stderr is never discarded,
including on a zero exit code: a `2>/dev/null` on a sweep once hid failures and
made a counting gap read as a regression. The `[FAIL]`/`[PANIC]` counts are how
many entries are missing from the numbers above them, and they are reported as
such.

`drakkar.complete` is true only when Drakkar exited 0, did not time out, was not
cancelled and its stdout was not cut. `complete: false` means partial output,
whatever the files look like.

Every call that ran Drakkar also leaves `envelope.json` in its output directory:
the whole envelope, the on-disk record of what the call gave, even when the
answer never reached the client.

## Background jobs

A client or a bridge that gives up on a request cancels it, and Drakkar with it.
Any call that may run past a minute — a bulk `directory`, the diffs and the
matrix, `drakkar_decompile`, `drakkar_bundle`, `drakkar_scan`,
`drakkar_dart_snapshot`, `drakkar_native` with `disasm`, and every other native
mode but `drakkar_native_arch` — should therefore pass `"background": true` with
an `out_dir`:

```text
drakkar_native_xrefs {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/xrefs",
                      "addresses": ["1a00"], "background": true}
→ answers at once: a job_id, and a note that nothing has been measured yet

drakkar_job_status {"job_id": "<job_id>"}
→ state (running, done, failed, cancelled), elapsed time and, once ended, the envelope
```

The job writes `job.json` and, once it has ended, `envelope.json` in its
`out_dir`, so `drakkar_job_status` with `out_dir` instead of `job_id` still works
after a restart of the server. `done` means Drakkar ran to an end, not that the
run was whole: read `envelope.drakkar.complete`. A `job.json` still at `running`
that no server holds any more is reported as `orphaned`: its output is partial
and nothing will finish it.

`drakkar_job_cancel` kills Drakkar and still writes `envelope.json`, with
`cancelled: true` and `complete: false`; only the server process that started a
job can cancel it. At most `DRAKKAR_MAX_JOBS` jobs run at once, and a call past
that limit is refused with the way out.

### Reading a sample through its bundle

`drakkar_decompile` and `drakkar_bundle` need Drakkar 0.2.0; against an older
one they refuse with a message saying so. `drakkar_bundle` is one of the three tools
whose `out_dir` is required — the others are `drakkar_dart_snapshot` and
`drakkar_native_strings`: the bundle is
a deliverable, written to `OUT/<sha256 of the input>/`, never to a temporary
directory. The two readers run no analysis — they read that directory, and call
nothing but `drakkar --version`, to refuse alongside the others when the Drakkar
on `PATH` predates 0.2.0.

An agent that has to go through a sample does it in three steps:

```text
1. drakkar_bundle        {"input": "/corpus/sample.apk", "out_dir": "/cases/2026-10/bundles"}
   → result.bundle_dir = /cases/2026-10/bundles/<sha256>
     result.bundle, errors_total, per_origin, per_decompile_status, tails.errors

2. drakkar_bundle_index  {"bundle_dir": "/cases/2026-10/bundles/<sha256>",
                          "has_rules_direct": true, "origin": "app"}
   → tails.classes: the application classes a rule cites directly

3. drakkar_bundle_class  {"bundle_dir": "/cases/2026-10/bundles/<sha256>", "id": 42}
   → result.class, result.parts.{class_java, java, dasm, methods}, result.errors
```

Prioritise on `rules_direct`, never on `rules_path`: a rule's path starts at an
entry point or at a rule's pivot, so `rules_path` cites every class it traverses.
`origin: app` is over-inclusive — a library missing from Drakkar's exclusion
list, or renamed by ProGuard, counts as app. And the Java is read against the
`.dasm`: dex-decompiler is young, and a decompile status of `ok` does not
guarantee fidelity. `drakkar_legend` with topic `bundle` defines every file and
field.

To hand a bundle to an import service, pass `"archive": true` (Drakkar 0.3.0).
Drakkar then also writes `OUT/<sha256>.bundle.zip`, every entry under
`<sha256>/`, byte-identical for identical directory content, and the answer
gains `archive_path`, `archive_size` and `archive_sha256` as Drakkar reports
them — the hash whole, never recomputed here. That file is the one to upload.
With `overwrite`, an existing archive is replaced, or deleted when `archive` is
not set, so it never outlives the bundle it was made from. An older Drakkar
refuses the flag, and its message comes back as it is in `stderr`.

From 0.3.0, `bundle.json` also carries `schema_version` (the version of the
bundle's structure), `input_size` (bytes) and `rules_hash` (the whole SHA-256
of the rule set and MITRE catalogue behind `rules.json`, null when `rules.json`
is null). They come back unfiltered in `result.bundle`.

## Native code

Nine tools read the native side of a sample, nothing executed. `drakkar_native`
is the entry point: it finds every ELF by content, binds the DEX native methods
to it, and gives the `elfs[].path` the other tools take as `elf`. From there:

- strings first, with `drakkar_native_strings`, or per function with
  `drakkar_native_labels`, to name the functions of a stripped binary;
- what refers to an address, with `drakkar_native_xrefs`, and what a block of
  data holds, with `drakkar_native_words` and `drakkar_native_vtables`;
- the instructions of a function, with `drakkar_native` `listing`, and where a
  value comes from, with `drakkar_native_symex`.

The five modes that work on addresses of an AArch64 ELF — `drakkar_native_symex`,
`drakkar_native_xrefs`, `drakkar_native_words`, `drakkar_native_vtables` and
`drakkar_native_labels` — share their conventions. Each takes one APK or one raw
ELF recognised by its magic. The server checks the form of a parameter only — hex
addresses, list sizes, integers not negative — refuses before Drakkar runs when
it is wrong, and leaves every other refusal to Drakkar. A parameter left out adds
no option, so Drakkar's default applies. When Drakkar refuses a call and writes no
report, its message comes back verbatim in `errors` and in the notes; for
`drakkar_native_words`, `drakkar_native_vtables` and `drakkar_native_labels`, a
note also says whether that Drakkar lacks the mode itself or only one of its
options. A field absent from a report stays absent, and `drakkar_legend` with
topic `native` defines every field, in one section per mode.

### Binding and disassembling native code

`drakkar_native` runs `drakkar <apk> --native`: every ELF of the APK, found by
content (`lib/`, `assets/`, `res/raw/`, elsewhere), or one raw ELF recognised by
its magic; its JNI exports and the `JNINativeMethod` tables rebuilt through
relative relocations; and the binding of the DEX native methods to them
(`static`, `registered`, `registered_ambiguous`, `declared_unbound`,
`native_unclaimed`). With `disasm` it adds `--native-disasm`: the static
disassembly of every JNI-bound function, `JNI_OnLoad` and the `init_array`
constructors, with JNIEnv calls decoded, PLT imports called and strings
referenced. Nothing is executed and nothing is extracted; `drakkar_extract_libs`
is the tool for the files themselves.

```text
drakkar_native {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/native",
                "disasm": true, "disasm_depth": 2,
                "listing": ["lib/arm64-v8a/libfoo.so@0x1a00"]}
→ argv: /corpus/sample.apk --native --native-disasm --disasm-depth=2
        --native-listing=lib/arm64-v8a/libfoo.so@0x1a00
        --format=json --json-out=/cases/2026-11/native/report.json
  result: sha256, dex_available, dex_sources, the report's summary (elf_count,
          native_methods_declared, bound_static, bound_registered, ambiguous,
          unbound, unclaimed); with disasm, disasm_functions_total,
          disasm_truncated, jni_calls_resolved, jni_calls_unresolved
  tails.elfs: path, origin, sha256, machine, bits, elf_type, stripped, jni_onload,
              jni_registration, static_exports_count, registered_count,
              anomalies, invalid_paths_count
  tails.binding: the report's rows, sorted by status then java
  tails.disasm_functions: elf, elf_sha256, origin, address, disasm_status, truncated,
                          truncated_reason, invalid_paths, instructions_count,
                          calls_count, imports_called, jni_calls,
                          jni_calls_unresolved, string_refs, string_refs_total
  tails.upcalls, tails.registered_by_code: elf, class, name, signature
  tails.listings: elf, start, end, instructions[], instructions_total, truncated
  tails.errors
  report_path = /cases/2026-11/native/report.json
```

| Parameter | |
|---|---|
| `apk` | required, absolute: one APK, or one raw ELF |
| `native_dex` | `--native-dex`, repeatable: absolute paths of APKs or raw DEX files whose native methods are bound in addition to the APK's own; it is what binds a raw ELF, and with an APK it adds a decrypted payload DEX. The head's `dex_available` and `dex_sources` say what was read |
| `disasm` | `--native-disasm` |
| `disasm_depth` | with `disasm` only, `--disasm-depth`: how deep local calls are followed, 0 to 3 |
| `disasm_max_insns` | with `disasm` only, `--disasm-max-insns`: instruction budget per function, 1 to 20000, past which the function is marked truncated |
| `listing` | with `disasm` only, `--native-listing`, repeatable: `<elf path\|*>@<hex address>` for a function, `<elf path\|*>@<hex start>-<hex end>` for a range, end excluded; the elf path is `elfs[].path`, the file name for a raw ELF |
| `listing_only` | with `listing` only: return the listings alone, as described below; adds no option |
| `max_rows` | `binding` rows, `disasm_functions` rows and instructions per listing returned inline; with `listing_only`, instructions per listing only |
| `out_dir`, `background`, `timeout_seconds` | as for every tool; the timeout is the fast class (`DRAKKAR_TIMEOUT_FAST`), the diff class (`DRAKKAR_TIMEOUT_DIFF`) with `disasm` |

A parameter left out adds no option, so Drakkar's default applies. The server
refuses before Drakkar runs a disasm option without `disasm`, `listing_only`
without `listing` or without `disasm`, a bound out of range and a relative
`native_dex`.

The head is the report's summary. `elfs`, `upcalls`, `registered_by_code` and
`errors` come back whole; `binding` and `disasm_functions` are cut at
`max_rows`. A `disasm_functions` row keeps the counts and leaves the
instructions, the calls and the `invalid_paths` objects in `report.json`; its
`string_refs` stop at 20, with `string_refs_total`. `invalid_paths_count` is null
without `disasm` or from a Drakkar older than 0.2.3. When the report has errors,
a note recalls that a DEX that could not be read leaves its native methods out of
the binding. `drakkar_legend` with topic `native` defines `invalid_paths`,
`invalid_paths_count` and the `opaque_dead_code` anomaly.

**Reading one function.** Each `listing` comes back in the `listings` tail as
readable assembly — `address`, `bytes`, `mnemonic`, `operands` and a
per-instruction `comment` — cut at `max_rows` instructions, with
`instructions_total` and `truncated` per listing. A listing Drakkar cannot
produce is reported in `errors`. Without `listing_only`, the same `max_rows`
also cuts `binding` and `disasm_functions`: an 800-instruction function asks for
`max_rows` 800, and brings back up to 800 `disasm_functions` rows with it.

`listing_only` keeps the answer to the listings. The argv does not change and
Drakkar writes the same report; only the answer does. `disasm_functions`,
`binding`, `upcalls` and `registered_by_code` come back with no item, `returned`
at 0, their exact `total`, and `truncated` whenever that total is not 0; the
head, `elfs`, `errors` and `listings` are unchanged, and a note says what was
withheld. Everything is still in `report_path`.

```text
drakkar_native {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/native",
                "disasm": true, "listing": ["lib/arm64-v8a/libfoo.so@0x1a00"],
                "listing_only": true, "max_rows": 800}
→ argv: /corpus/sample.apk --native --native-disasm
        --native-listing=lib/arm64-v8a/libfoo.so@0x1a00
        --format=json --json-out=/cases/2026-11/native/report.json
  tails.listings: the function, up to 800 instructions
  tails.disasm_functions, binding, upcalls, registered_by_code: total only
```

### Extracting native strings

`drakkar_native_strings` (Drakkar 0.6.0) runs `drakkar <input> --native-strings`:
the strings of every ELF in an APK, an XAPK (base and ABI splits) or a raw ELF,
each with its address, section, encoding and how its boundary was found, plus the
cryptographic constants recognised by content.

```text
drakkar_native_strings {"input": "/corpus/sample.apk", "out_dir": "/cases/2026-11/strings",
                        "patterns": ["http", "-key"], "xrefs": true, "crates": true}
→ argv: /corpus/sample.apk --native-strings=http --native-strings=-key --xrefs --crates
        --format=json --json-out=/cases/2026-11/strings/<sha256>.native_strings.json
  tails.elfs: elf, split, elf_sha256, machine, Drakkar's summary as is,
              crates, c_libraries, crypto_constants
  tails.strings, tails.format_arrays (Drakkar 0.6.1), tails.elfs_not_selected, tails.errors
  report_path = /cases/2026-11/strings/<sha256>.native_strings.json
```

| Parameter | |
|---|---|
| `input` | required, absolute: one APK, one XAPK, or one raw ELF |
| `out_dir` | required, absolute, no fallback: a large library yields hundreds of thousands of strings |
| `patterns` | `--native-strings`, repeatable: case-insensitive substrings; only the matching strings are kept, while the counts, `crates`, `c_libraries` and `crypto_constants` still cover every string |
| `min_length` | `--min-length`: minimum length in characters, at least 1 |
| `elf` | `--elf`: one ELF, by entry path, `<split>!<entry>` in an XAPK, or file name for a raw ELF |
| `xrefs` | `--xrefs`: for each string and constant, the AArch64 instructions forming its address and the function holding them |
| `crates` | `--crates`: the Rust crates named by source paths, and the banners of statically linked C libraries |
| `max_rows` | strings, and separately format arrays, returned inline across every ELF |
| `background`, `timeout_seconds` | as above; the timeout is the diff class |

`boundary` says how much of a string is proven: `nul` (text ending on a NUL
byte, only its end proven), `rust_fatptr` (a relocated Rust `&str` `{ptr, len}`
pair, start and end proven), `rust_code` (an address formed in AArch64 code
paired with an immediate length, proven but open to false positives such as a
`memcpy`'s source and size) and `heuristic` (no proven bound). `format_arrays`
lists each array of contiguous `{ptr, len}` pairs, the pieces of a Rust format
string or a table of `&str`; an entry of an array whose references were not
propagated can have an empty `xrefs` while its table is referenced.

An empty `xrefs` is not evidence that a string is unused: computed addresses, an
ADRP and its ADD far apart, encrypted or generated code and reads from another
library escape the scan. `rust_code` and `xrefs` exist only for AArch64. Every
`[AVERT]` and `[FAIL]` line of stderr comes back as a note. `drakkar_strings` is
the tool for the DEX string pool; `drakkar_legend` with topic `native_strings`
defines every field.

### Following a value through a native function

`drakkar_native_symex` runs `drakkar <apk> --native --native-symex=<function>`
with the options below: a propagation of symbolic values through one AArch64
function, path by path, with no execution and no solver. It answers where the
value read or written at each watched instruction comes from. The mode is in
Drakkar 0.6.1 as its `main` declares it in `Cargo.toml` (the `v0.6.1` tag predates
it); a Drakkar without it refuses the option, and its message comes back verbatim
in `errors` and in the notes.

```text
drakkar_native_symex {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/symex",
                      "function": "lib/arm64-v8a/libfoo.so@1a00",
                      "watch": ["1a40", "1a58"],
                      "peek": ["1a40:x1+0x10:16", "1a58:sp+8:8"],
                      "background": true}
→ argv: /corpus/sample.apk --native --native-symex=lib/arm64-v8a/libfoo.so@1a00
        --native-symex-watch=1a40,1a58 --native-symex-peek=1a40:x1+0x10:16,1a58:sp+8:8
        --format=json --json-out=/cases/2026-11/symex/report.json
  result.symex[]: elf, fn_start, fn_end, bound, entry, directed, budgets, paths_explored,
                  paths_cut, budget_hit, callees_abandoned, callees_incomplete,
                  forks_dropped, rounds, watches_count, calls_count, indirect_branches_count
  tails.watches: insn_addr, instruction, reached, results[] (by paths, cut at max_rows)
  tails.calls, tails.indirect_branches, tails.errors
  report_path = /cases/2026-11/symex/report.json
```

| Parameter | |
|---|---|
| `apk` | required, absolute: one APK, or one raw ELF |
| `function` | required: `<elf path\|*>@<hex address>`, passed as is to `--native-symex`; `*` takes every AArch64 ELF whose executable code holds the address |
| `watch` | hex addresses of the instructions to observe, joined into `--native-symex-watch`; Drakkar refuses a run without one |
| `peek` | `<watch>:<register>+<offset>:<length>` items, joined into `--native-symex-peek`: bytes of the symbolic memory just before that watch |
| `entry` | `--native-symex-entry`: hex address inside the function to start from |
| `depth`, `max_insns`, `max_paths`, `fragment_max`, `callee_forks`, `refine` | `--native-symex-depth`, `-max-insns`, `-max-paths`, `-fragment-max`, `-callee-forks`, `-refine` |
| `follow` | hex addresses of `bl` (or `b`) whose callee is followed whatever the depth, joined into `--native-symex-follow` |
| `undirected` | `--native-symex-undirected`: neither pruning nor ordering by distance to the watches |
| `out_dir`, `background`, `max_rows`, `timeout_seconds` | as for `drakkar_native`; the timeout is the class of `drakkar_native` with `disasm` |

A parameter left out adds no option, so Drakkar's default applies. The server
checks the form only — hex addresses (`0x` optional, as Drakkar reads them),
integers not negative, no empty item — and leaves every other refusal to Drakkar.

Each watch comes back with all its fields and its `results` sorted by `paths`
descending, cut at `max_rows` per watch, with `results_total` and
`results_truncated`; each result keeps its expressions (text and tree), `trace`,
`trace_truncated` and `peeks` whole. Each row of `watches`, `calls` and
`indirect_branches` also carries the `elf` and `fn_start` of its symex entry,
since `*` may yield one entry per ELF. A field absent from the report stays
absent. `drakkar_legend` with topic `native` defines every field, status and
expression form in its SYMEX section.

### Finding what refers to a native address

`drakkar_native_xrefs` runs `drakkar <apk> --native --native-xrefs=<elf|*>@<addresses>`:
for each address of an AArch64 ELF, with no execution, the function that holds
it, the direct branches to it (a function's callers), the instructions that form
or access its address, and the data words that hold it (method tables). The mode
is in Drakkar 0.6.1 as its `main` declares it in `Cargo.toml` (the `v0.6.1` tag
predates it); a Drakkar without it refuses the option, and its message comes back
verbatim in `errors` and in the notes.

```text
drakkar_native_xrefs {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/xrefs",
                      "elf": "lib/arm64-v8a/libfoo.so",
                      "addresses": ["1a00", "0x5010"]}
→ argv: /corpus/sample.apk --native --native-xrefs=lib/arm64-v8a/libfoo.so@1a00,0x5010
        --format=json --json-out=/cases/2026-11/xrefs/report.json
  result.xrefs[]: elf, target, section, function,
                  code_refs {total, truncated}, addr_refs {total, truncated},
                  data_refs {total, truncated}
  tails.code_refs: insn_addr, mnemonic, kind, function, elf, target
  tails.addr_refs: insn_addr, adrp_addr, kind, function, elf, target
  tails.data_refs: vaddr, section, relocated, elf, target
  tails.errors
  report_path = /cases/2026-11/xrefs/report.json
```

| Parameter | |
|---|---|
| `apk` | required, absolute: one APK, or one raw ELF |
| `elf` | path of the ELF in the APK (`elfs[].path` of `drakkar_native`, the file name for a raw ELF), or `*`; omitted, `*`: every AArch64 ELF with an allocated section holding the address |
| `addresses` | required: 1 to 64 hex addresses, `0x` optional, joined after `<elf>@` into `--native-xrefs` |
| `max` | `--native-xrefs-max`: references Drakkar keeps per list and per address; totals stay exact |
| `out_dir`, `background`, `max_rows`, `timeout_seconds` | as for `drakkar_native_symex`, timeout class included |

A parameter left out adds no option, so Drakkar's default applies. The server
checks the form only — hex addresses, a list neither empty nor over 64 distinct
addresses, `max` not negative — and leaves every other refusal to Drakkar.

The head has one entry per ELF and address, with `function` as Drakkar gives it
(absent when the address is not in executable code) and the `total` and
`truncated` of each list. Each tail holds the items of every entry in the
report's order, each with the `elf` and `target` of its entry, cut at
`max_rows`; its total counts the items present in the report. When Drakkar cut a
list itself (`truncated`), a note gives the exact total and points to `max`. A
field absent from the report stays absent. `drakkar_legend` with topic `native`
defines every field and kind in its XREFS section.

No reference is not a proof of absence: an indirect branch (`br`, `blr`), a
computed address, an ADRP and its ADD or LDR far apart, a jump table, or code
that is encrypted or generated at run time escape the search. A target with no
reference in any of the three lists gets a note saying so.

### Reading native data words

`drakkar_native_words` runs `drakkar <apk> --native --native-words=<elf|*>@<ranges>`:
8-byte words read at addresses of an AArch64 ELF, with no execution, relative
relocations applied, and what each one designates. The mode is in Drakkar 0.6.1
as its `main` declares it in `Cargo.toml` (the `v0.6.1` tag predates it); a
Drakkar without it refuses the option, and its message comes back verbatim in
`errors` and in the notes.

```text
drakkar_native_words {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/words",
                      "elf": "lib/arm64-v8a/libfoo.so",
                      "ranges": ["36ffbd0:6", "0x4a3c08:3"]}
→ argv: /corpus/sample.apk --native --native-words=lib/arm64-v8a/libfoo.so@36ffbd0:6,0x4a3c08:3
        --format=json --json-out=/cases/2026-11/words/report.json
  result.ranges[]: elf, start, count, vtable_like, size, align
  tails.words: index, offset, vaddr, section, raw, value, relocated, kind, function,
               at_start, target_section, text, text_truncated, elf, start
  tails.errors
  report_path = /cases/2026-11/words/report.json
```

| Parameter | |
|---|---|
| `apk` | required, absolute: one APK, or one raw ELF |
| `elf` | path of the ELF in the APK (`elfs[].path` of `drakkar_native`, the file name for a raw ELF), or `*`; omitted, `*`: every AArch64 ELF with an allocated section holding the start of the range |
| `ranges` | required: 1 to 64 `<hex address>:<count>` items, `0x` optional, count decimal from 1 to 512, joined after `<elf>@` into `--native-words` |
| `out_dir`, `background`, `max_rows`, `timeout_seconds` | as for `drakkar_native_xrefs`, timeout class included |

The server checks the form only — each range `address:count`, a hex address, a
count from 1 to 512, 1 to 64 ranges — and leaves every other refusal to Drakkar,
an address not aligned on 8 among them.

The head has one entry per range as Drakkar gives it, without its words; `size`
and `align` are there only when `vtable_like` is true. The `words` tail holds the
words of every range in the report's order, each with the `elf` and `start` of its
range, cut at `max_rows`. `kind` is `code` (with `function` and `at_start`), `data`
(with `target_section`, and `text` and `text_truncated` when the target is text),
`int`, or `none` when the word has no bytes in the file (no `raw`, no `value`). A
field absent from the report stays absent. `drakkar_legend` with topic `native`
defines every field in its WORDS section.

`vtable_like` is a hint, not a proof: any three words can have the shape of a
Rust vtable header, and a note says so whenever one range has it;
`drakkar_native_vtables` is the tool that lists the tables. Only relative
relocations are applied: a word relocated by `R_AARCH64_ABS64` or by a packed
APS2 format keeps its file value. In a position-independent ELF a word that is
not relocated is always `int`.

### Listing Rust method tables

`drakkar_native_vtables` runs `drakkar <apk> --native --native-vtables=<elf|*>`
with the filters below: the Rust method tables (destructor, size, alignment,
methods) of an AArch64 ELF, recognised by their shape in read-only and RELRO
data, with no execution. The mode is in Drakkar 0.6.1 as its `main` declares it
in `Cargo.toml` (the `v0.6.1` tag predates it); a Drakkar without it refuses the
option, and its message comes back verbatim in `errors` and in the notes.

```text
drakkar_native_vtables {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/vtables",
                        "elf": "lib/arm64-v8a/libfoo.so",
                        "fn": ["36ffbd0"], "refs": true}
→ argv: /corpus/sample.apk --native --native-vtables=lib/arm64-v8a/libfoo.so
        --native-vtables-fn=36ffbd0 --native-vtables-refs
        --format=json --json-out=/cases/2026-11/vtables/report.json
  result.vtables[]: elf, tables_total, tables_matched, truncated
  tails.tables: vaddr, section, drop, size, align, methods_count, methods[],
                matched, addr_refs, data_refs, elf
  tails.errors
  report_path = /cases/2026-11/vtables/report.json
```

| Parameter | |
|---|---|
| `apk` | required, absolute: one APK, or one raw ELF |
| `elf` | path of the ELF in the APK, or `*`; omitted, `*`: every AArch64 ELF |
| `fn` | `--native-vtables-fn`: 1 to 64 hex addresses; keep the tables whose destructor or a method is one of them, each then with `matched`, the offsets where it was found (`0x0` for the destructor) |
| `slot` | `--native-vtables-slot`: offset, `0x` hex or decimal; keep the tables with a method there (Drakkar wants a multiple of 8, at least `0x18`) |
| `size` | `--native-vtables-size`: `0x` hex or decimal; keep the tables of that size |
| `at` | `--native-vtables-at`: 1 to 64 hex addresses; keep the tables starting at one of them |
| `max` | `--native-vtables-max`: tables Drakkar renders per ELF; `tables_total` and `tables_matched` stay exact |
| `refs` | `--native-vtables-refs`: the instructions forming and the data words holding each rendered table's address, that is who builds it |
| `out_dir`, `background`, `max_rows`, `timeout_seconds` | as for `drakkar_native_xrefs`, timeout class included |

A parameter left out adds no option, so Drakkar's default applies; filters
combine with AND. The server checks the form only — hex addresses, lists of 1 to
64 distinct addresses, `slot` and `size` in `0x` hex or decimal and passed as
given, `max` not negative — and leaves every other refusal to Drakkar.

The head has one entry per ELF with its counters as Drakkar gives them. The
`tables` tail holds every table whole, `methods` (offset, value, function),
`matched`, `addr_refs` and `data_refs` included when present, each with its
`elf`, cut at `max_rows`. When Drakkar cut the list itself (`truncated`), a note
gives `tables_matched` and `tables_total` and recalls the filters and `max`; an
ELF where no table matched gets a note too. A field absent from the report stays
absent. `drakkar_legend` with topic `native` defines every field in its VTABLES
section.

The mode returns candidates. A function in a table does not prove that a given
indirect call targets it. Detection is structural: a block of data with that
shape is rendered as a table, a table without method is not found, two adjacent
tables can be merged, and a table relocated other than by a relative relocation
(`R_AARCH64_ABS64`, packed APS2, an `ET_EXEC` without relative relocations) is
missed. No reference to a table is not a proof either: a computed address or an
ADRP and its ADD far apart escape `refs`.

### Labelling native functions by their strings

`drakkar_native_labels` runs `drakkar <apk> --native --native-labels=<elf|*>`
with the filters below: for each function of an AArch64 ELF, with no execution,
the strings it references and a readable label — the inverse index of
`drakkar_native_strings` xrefs. It serves to name the functions of a stripped
Rust binary and to find the functions referencing a text. The mode is on
Drakkar's `feat/native-labels` branch, not yet merged; a Drakkar without it
refuses the option, and its message comes back verbatim in `errors` and in the
notes.

The label is, in this order: a function name (`label_kind` `fn_name`: the
identifier after a leading `] `, or a lowercase bracketed tag holding `_`), else
a log tag (`log_tag`), else a `.rs` source path (`source_path`), else `none`. A
string reached through a small fragment called by more than `fragment_fanout`
functions is `shared`: it stays in `strings[]` but serves neither the label nor
`match`, and a function whose strings are all shared is rendered only when `fn`
asks for it.

```text
drakkar_native_labels {"apk": "/corpus/sample.apk", "out_dir": "/cases/2026-11/labels",
                       "elf": "lib/arm64-v8a/libapp.so",
                       "match": ["connect"], "strings_max": 20}
→ argv: /corpus/sample.apk --native --native-labels=lib/arm64-v8a/libapp.so
        --native-labels-match=connect --native-labels-strings-max=20
        --format=json --json-out=/cases/2026-11/labels/report.json
  result.labels[]: elf, functions_total, functions_matched, truncated, and every
                   other ELF-level counter of the report
  tails.functions: every field of each function as Drakkar writes it (fn_start, fn_end,
                   bound, label, label_kind, all_tags, strings_total, strings_truncated,
                   strings[] …), elf
  tails.errors
  report_path = /cases/2026-11/labels/report.json
```

| Parameter | |
|---|---|
| `apk` | required, absolute: one APK, or one raw ELF |
| `elf` | path of the ELF in the APK, or `*`; omitted, `*`: every AArch64 ELF |
| `fn` | `--native-labels-fn`: 1 to 64 hex addresses; keep the functions containing one of them |
| `match` | `--native-labels-match`: substrings, case ignored; keep the functions with a string containing one of them |
| `max` | `--native-labels-max`: functions Drakkar renders per ELF; `functions_total` and `functions_matched` stay exact |
| `strings_max` | `--native-labels-strings-max`: strings Drakkar renders per function; `strings_total`, `label` and `all_tags` stay computed on all of them |
| `fragment_fanout` | `--native-labels-fragment-fanout`: callers above which a string reached through a small fragment is shared, kept out of `label`, `names`, `all_tags` and `match` |
| `out_dir`, `background`, `max_rows`, `timeout_seconds` | as for `drakkar_native_xrefs`, timeout class included |

A parameter left out adds no option, so Drakkar's default applies; filters
combine with AND. The server checks the form only — hex addresses, a list of 1 to
64 distinct addresses, patterns neither empty nor holding a comma (Drakkar splits
on it), integers not negative — and leaves every other refusal to Drakkar.

The report of this mode is still evolving, so nothing is filtered or renamed: the
head carries every ELF-level field but the `functions` array, and the `functions`
tail every field of each function, unknown ones included, plus its `elf`, cut at
`max_rows`. When Drakkar cut the list itself (`truncated`), a note gives
`functions_matched` and `functions_total` and recalls the filters and `max`; an
ELF where no function matched gets a note too. A field absent from the report
stays absent. `drakkar_legend` with topic `native` defines every field in its
LABELS section.

The label is a reading aid, not a proven name. A string attached through a small
fragment (`via_fragment`) belongs to one of the fragment's callers, not
necessarily to all of them; an indirect, conditional or inner call to the
fragment is not seen. A function whose strings escape the scan — a computed
address, an ADRP and its ADD far apart — does not appear.

### Reading a Flutter snapshot

`drakkar_dart_snapshot` (Drakkar 0.5.0) reads the four `_kDart*Snapshot*` blobs
of each `lib/*/libapp.so`, located by `.dynsym` or, failing that, by the snapshot
magic — or of one raw ELF passed as `apk` and recognised by its magic. Nothing is
extracted and nothing is executed.

```text
drakkar_dart_snapshot {"apk": "/corpus/flutter.apk", "out_dir": "/cases/2026-11/dart",
                       "calibrate": ["Hello world", "api/v1/login", "Bearer "]}
→ result.sha256, result.summary
  tails.libraries: path, sha256, sections[], missing_symbols, strings_unavailable, anomalies
  tails.errors
  report_path = /cases/2026-11/dart/report.json
```

| Parameter | |
|---|---|
| `apk` | required, absolute: one APK, or one raw ELF |
| `out_dir` | required, absolute, no fallback: `report.json` holds every string entry |
| `max_rows` | Drakkar's `--dart-max-rows`, omitted unless set: how many entries per data image Drakkar writes into `report.json`, `0` for all. Never a preview size — the entries never come back inline |
| `calibrate` | witnesses, repeatable: texts expected in clear in the data image, each one visible in the argv; an empty or blank witness is refused |

Each row of `sections` carries `symbol`, `blob_index`, `file_offset`, `vaddr`,
`size`, `elf_section`, the `header` (`magic_ok`, `length`, `kind`,
`version_hash` whole, `known_version`, `features`, `compressed_pointers`,
`errors`), the `serialized` and `data_image` spans, and for a data blob the
counters of its string scan (`candidates`, `accepted`, `rejected`,
`entries_total`, `entries_returned`, `truncated`) and `strings_unavailable`.

**The string entries never come back inline.** A real Flutter APK yields more
than 80 000 of them; they are in `report.json` under
`libraries[].sections[].strings.entries`, and the counters say how many there are
and whether `max_rows` cut them. The enumeration is heuristic and only runs for a
snapshot version Drakkar knows or a layout calibration found.

**Calibration is optional.** Without a witness no calibration runs, and the
sections carry no `calibration` at all. With witnesses, each data blob gets one:
`outcome`, `not_run_reason`, `witnesses_total`, `witnesses_found`,
`witnesses_in_data_image`, `witnesses_explained`, `data_image_verdict`,
`witness_zones` (the witnesses' occurrences summed per zone: serialized part,
data image, outside), `inferred`, `word_size`, `known_version_literal`. `outcome`
is `not_run` when witnesses were given but the blob's strings cannot be read, and
`not_run_reason` says why; too few witnesses is `insufficient_witnesses`. The
per-witness detail, and the evidence of each inferred layout, come back inline
only when they are a handful; past that only the counts are here, and the detail
is in `report.json`.

`drakkar_legend` with topic `dart_snapshot` prints Drakkar's own definition of
every field: what `heuristic` means, the values of `layout_source`, the keys of
`rejected`, and the calibration outcomes (`calibrated`, `insufficient_witnesses`,
`witness_not_found`, `witnesses_not_all_found`, `witnesses_outside_data_image`,
`no_layout_explains_witnesses`, `ambiguous_layout`, `not_run`).

## Design rules

- **Typed paths, never a command string.** `exec.Command` with separate
  arguments. No shell interpolation, no `sh -c`, anywhere.
- **Whole hashes.** Every SHA-256 is whole, in output, summaries and error
  messages alike. A truncated hash passed as a filter is refused, not forwarded,
  and the offending value is echoed in full: a silently accepted prefix is how a
  filter comes back empty and gets read as the absence of the asset.
- **No duplicated defaults.** Where Drakkar has a default, the flag is omitted and
  Drakkar decides. The parameters are nil-able and the descriptions do not restate
  the value either — a number copied into a description drifts just as surely as
  one copied into the code. `drakkar_legend` is where the values live.
- **Bounded timeouts and bounded output.** Per class of mode, overridable per
  call. On a timeout the child is killed and whatever it had already written is
  still returned: discarding partial output is how a killed scan reads as a clean
  one.
- **One invocation, one representation.** `--format both` is never used. That also
  sidesteps [drakkar#9](https://github.com/sebdraven/drakkar/issues/9), where
  `--diff-explain` mixes the two streams on stdout.
- **`--out` is always passed explicitly.** Drakkar defaults it to `./reports`,
  relative to the working directory — which for a server started by an MCP client
  is arbitrary. This is the one place a Drakkar default is deliberately overridden,
  because it is a boundary and not a setting.

`--color` is *not* passed: `auto` already emits no ANSI when stdout is not a
terminal, and it never is here. One fewer duplicated default.

## What is deliberately not exposed

- **`--enrich`.** Not because it is redundant — `mcp-virustotal` and `mcp-koodous`
  do unit lookups, while `--enrich` does bulk enrichment with a response cache and
  per-service rate limiting, which is a different function and not available
  elsewhere. It is a capability given up on purpose, so that this server never has
  to hold `VT_API_KEY` or `KOODOUS_TOKEN`. The child environment is built
  explicitly — `PATH`, `HOME`, `TMPDIR`, `RUST_LOG` — rather than inherited, so no
  token reaches Drakkar through it even if one is set here.
- **`--assets-hash-file`, `--assets-hash-exclude-file` and
  `--dart-calibrate-file`.** The hashes and the calibration witnesses pass inline
  instead, which keeps them visible in the `argv` the envelope reports rather
  than hidden behind a file path.
- **`--rules`.** Pointing the engine at a different rule directory is a
  bench-configuration decision, not a per-measurement one.
- **`--matrix-top`.** It truncates the text ranking only; the JSON report carries
  every pair regardless. Exposing it would imply a bound on the answer that it
  does not place.

`drakkar_scan` and `drakkar_bundle` are the two tools that reach the network: the
rule engine loads the MITRE catalogue, and a first call after a cache miss
downloads it.

## What is deliberately not exposed

- **`--enrich`.** Not because it is redundant — `mcp-virustotal` and `mcp-koodous`
  do unit lookups, while `--enrich` does bulk enrichment with a response cache and
  per-service rate limiting, which is a different function and not available
  elsewhere. It is a capability given up on purpose, so that this server never has
  to hold `VT_API_KEY` or `KOODOUS_TOKEN`. The child environment is built
  explicitly — `PATH`, `HOME`, `TMPDIR`, `RUST_LOG` — rather than inherited, so no
  token reaches Drakkar through it even if one is set here.
- **`--assets-hash-file`, `--assets-hash-exclude-file` and
  `--dart-calibrate-file`.** The hashes and the calibration witnesses pass inline
  instead, which keeps them visible in the `argv` the envelope reports rather
  than hidden behind a file path.
- **`--rules`.** Pointing the engine at a different rule directory is a
  bench-configuration decision, not a per-measurement one.
- **`--matrix-top`.** It truncates the text ranking only; the JSON report carries
  every pair regardless. Exposing it would imply a bound on the answer that it
  does not place.

`drakkar_scan` and `drakkar_bundle` are the two tools that reach the network: the
rule engine loads the MITRE catalogue, and a first call after a cache miss
downloads it.

## Layout and tests

```
cmd/mcp-drakkar/      the -version flag, startup diagnostics, stdio transport
internal/drakkar/     the flag whitelist, the argv builder, the runner, the stderr
                      marker parser, the TSV parsers
internal/service/     one mode to one answer: output directory, head/tail split,
                      declared truncation, background jobs, report writing
internal/mcptools/    the 38 tools, their descriptions and the server instructions
internal/version/     what the server declares about itself
```

**No test invokes `drakkar`.** The whitelist is tested on the argv it produces,
the TSV parsers on fixtures, the head/tail split on decoded reports, the refusals
against a stub `drakkar` script, the output directory on a temporary directory,
and the tool registration over an in-memory MCP transport. So CI needs no Rust
toolchain, no samples, and no macOS.

## Releases

Tag `vX.Y.Z`. The workflow refuses a tag that disagrees with `Version` in
`internal/version/version.go` — which is why that constant is declared in the
source rather than injected at link time: a version that only ever comes from
`-ldflags` can never disagree with the tag. Only the commit is injected;
`DrakkarTested` is a constant too, and the target and Go version come from the
runtime, so the release workflow never restates a value that lives in the code.

One leg per target builds and uploads its own binary and checksum;
`darwin/arm64` is built natively rather than cross-compiled. No Docker, no
published `go install` path.

## CI

`gofmt -l`, `go vet`, `go test -race`, `go build`, and `zizmor` over
`.github/workflows/`. Go is pinned to the patch, not `stable`, so two runs three
months apart are comparable. Every action is pinned by commit SHA.

zizmor is installed from the project's own precompiled archive, its checksum
pinned here and checked, then `gh attestation verify` binds that archive to
zizmor's own release workflow — the checksum covers a swapped or corrupted
download, the attestation covers their build. No dependency is installed and no
third-party action is used; `gh` and `curl` are already on the runner.

It starts **advisory**: `--no-exit-codes` makes zizmor exit 0 even with findings,
so the job is green on purpose rather than through a `continue-on-error` that is
easy to forget to remove. Turning it blocking is deleting one flag. Its report goes
to the job summary, not just the logs.

## Git hooks

`.githooks/pre-commit` and `.githooks/pre-push` run the lint steps of
`ci.yml` as they stand there: `gofmt -l ./cmd ./internal`, then `go vet ./...`.
Enable them once per clone:

```
git config core.hooksPath .githooks
```

When gofmt fails, run `gofmt -w .` and commit again.

## Related

- [Drakkar](https://github.com/sebdraven/drakkar) — the analysis engine this
  server exposes.

## Acknowledgements

This work is part of the DEFMAL project, funded by the French National
Research Agency (ANR) under France 2030, reference ANR-22-PECY-0007.

## Licence

MIT. See [LICENSE.md](LICENSE.md).
