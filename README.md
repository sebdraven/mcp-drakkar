# mcp-drakkar

An MCP server exposing [Drakkar](https://github.com/sebdraven/drakkar), a static
analysis engine for Android APKs and raw DEX files, as one tool per analysis mode.

It exists to remove three specific failure modes of running those measurements by
hand and pasting the output into a conversation:

1. **Paths with spaces, badly escaped.** The corpus lives under directories named
   `pCloud Drive` and `These`. `exec.Command` takes a `[]string`; there is no
   shell, so there is nothing to escape.
2. **Invented flags.** `--diff-json` was once proposed and does not exist. Here
   every parameter is typed and maps to an entry in a whitelist built from
   Drakkar's own clap struct: a flag that does not exist is not refused, it is
   inexpressible.
3. **`awk` over TSV columns.** Six modes have no JSON at all, so the TSV is not a
   rendering choice there — it is the only output. The parsing moves out of the
   conversation and into tested Go, once, with the header read rather than
   assumed.

## Configuration

None. There is nothing to declare in advance:

```json
{
  "mcpServers": {
    "drakkar": {
      "command": "mcp-drakkar"
    }
  }
}
```

Paths are tool parameters, given per call, the way they are in a shell. They must
be **absolute** — a relative path would be resolved against the child's working
directory, which is the call's output directory and not your shell.

Output goes wherever the call's `out_dir` says. Three tools require it,
`drakkar_bundle`, `drakkar_dart_snapshot` and `drakkar_native_strings`, and
refuse a call without it. For
every other tool, omitted, the server makes a fresh directory under the system
temp directory and returns its path in `report_path`. That fallback exists for
one reason: Drakkar's own `--out` defaults to `./reports` *relative to the
working directory*, which for a server started by an MCP client is arbitrary.
The server never lets that default apply — it substitutes an absolute directory
and says where it is.

Optional, all Go durations:
`DRAKKAR_TIMEOUT_FAST` (2m), `DRAKKAR_TIMEOUT_DIFF` (10m),
`DRAKKAR_TIMEOUT_MATRIX` (1h), `DRAKKAR_TIMEOUT_BULK` (1h).

`drakkar` must be on the `PATH`. **This server never builds, installs or
downloads it**; if it is absent, `drakkar_version` says so and every other tool
refuses with the same message.

## Tools

| Tool | What it answers |
|---|---|
| `drakkar_version` | which Drakkar is in use, which one this server was written against, the timeouts, and where output lands by default |
| `drakkar_legend` | Drakkar's own legend for a mode: where a metric's limits are stated; topic `native` covers `drakkar_native`, including its disasm labels, `drakkar_native_symex` in its SYMEX section, `drakkar_native_xrefs` in its XREFS section, `drakkar_native_words` in its WORDS section, `drakkar_native_vtables` in its VTABLES section and `drakkar_native_labels` in its LABELS section, topic `dart_snapshot` covers `drakkar_dart_snapshot`, and topic `native_strings` covers `drakkar_native_strings` |
| `drakkar_manifest` | permissions, components, intent filters, derived entry points |
| `drakkar_cert` | signature schemes v1/v2/v3/v3.1 and the X.509 certificates |
| `drakkar_dating` | raw dating indicators — no date is ever estimated |
| `drakkar_native` | every ELF found by content, its JNI exports and tables, and the binding of DEX native methods to them; with `disasm`, the static disassembly of every JNI-bound function, `JNI_OnLoad` and the `init_array` constructors — JNIEnv calls decoded, PLT imports called, strings referenced — bounded by `disasm_depth` (0–3) and `disasm_max_insns` (1–20000), instructions left in `report.json`; each `disasm_functions` row counts its `invalid_paths` and each `elfs` row carries `invalid_paths_count` (null without `disasm` or before Drakkar 0.2.3), both defined by `drakkar_legend` topic `native` |
| `drakkar_native_symex` | static symbolic propagation, with no execution, through one AArch64 function of an ELF: the symbolic value at each watched instruction, the calls met on the way and, on request, the bytes of memory a register points to — see [below](#following-a-value-through-a-native-function) |
| `drakkar_native_xrefs` | static cross-references, with no execution, to addresses of an AArch64 ELF: the function holding each one, the branches to it, the instructions forming its address and the data words holding it — see [below](#finding-what-refers-to-a-native-address) |
| `drakkar_native_words` | 8-byte words read, with no execution, at addresses of an AArch64 ELF, relative relocations applied: what each designates (a function's start or inside, data with a text preview, an integer) and whether a range looks like a Rust vtable header — a hint, not a proof — see [below](#reading-native-data-words) |
| `drakkar_native_vtables` | the Rust method tables of an AArch64 ELF, found by their shape with no execution, filtered by function, slot, size or address, and on request who builds each one — candidates, not proofs — see [below](#listing-rust-method-tables) |
| `drakkar_native_labels` | per function of an AArch64 ELF, with no execution, the strings it references and a readable label from its log tags or source paths, to name the functions of a stripped Rust binary — a reading aid, not a proven name — see [below](#labelling-native-functions-by-their-strings) |
| `drakkar_native_arch` | ABI, word size and machine of each `.so` under `lib/` |
| `drakkar_dart_snapshot` | the Dart AOT snapshot blobs of a Flutter app's `libapp.so`: where each blob is, its header (`version_hash` whole, `kind`, `features`, `compressed_pointers`), the serialized / data image split, and per section the counts of a heuristic string enumeration whose entries stay in `report.json`; calibration is optional and needs witnesses, `out_dir` is required — see [below](#reading-a-flutter-snapshot) |
| `drakkar_native_strings` | the strings of every ELF in an APK, an XAPK (base and ABI splits) or a raw ELF, each with how its boundary was found (`nul`, `rust_fatptr`, `rust_code`, `heuristic`), plus cryptographic constants and `format_arrays`, the arrays of contiguous Rust `{ptr, len}` pairs (format string pieces or `&str` tables); with `xrefs`, the AArch64 instructions forming each address; with `crates`, Rust crates and statically linked C libraries. Per ELF the summary comes back as is, the strings and the format arrays as two previews, each cut at `max_rows` with its total; the whole report is `<out_dir>/<sha256>.native_strings.json`. `out_dir` is required; needs Drakkar 0.6.0, and 0.6.1 for `format_arrays` |
| `drakkar_strings` | the DEX string pool, whole or filtered |
| `drakkar_disasm` | selected classes disassembled with operands resolved |
| `drakkar_decompile` | selected classes decompiled to Java by dex-decompiler, to check against `drakkar_disasm` |
| `drakkar_bundle` | everything Drakkar extracts from one sample, every class disassembled and decompiled, under `OUT/<sha256>/` |
| `drakkar_bundle_index` | the classes of a bundle, filtered — the tool for choosing what to read |
| `drakkar_bundle_class` | one class of a bundle: whole-class Java, per-method Java, `.dasm`, per-method records |
| `drakkar_dyn_entrypoints` | components reached other than by a manifest declaration |
| `drakkar_reflection_inputs` | where the name of each reflection target comes from |
| `drakkar_api_surface` | the protocol the sample declares: Retrofit verbs and routes, `@Path`/`@Query` names, Gson `@SerializedName` keys |
| `drakkar_orphan_audit` | methods unreachable from the roots, in islands, over four root stages |
| `drakkar_probe_api` | is this one API a graph node, and is it reachable, with paths |
| `drakkar_diff_dex` | same source tree? opcode fingerprints, blind to operands by design |
| `drakkar_diff_explain` | what actually differs in the operands of matched methods |
| `drakkar_diff_strings` | what differs in the string pools, where `static final` values live |
| `drakkar_diff_matrix` | all-against-all over a directory, plus single-linkage groups |
| `drakkar_resources` | resolve, dump, cross-reference or find unreferenced resources |
| `drakkar_assets` | inventory, fingerprint or extract the `assets/` entries |
| `drakkar_list_entries` | every entry path in the archive; nothing extracted |
| `drakkar_extract_entry` | extract matching entries only — never the whole archive |
| `drakkar_extract_libs` | every native ELF, including the ones outside `lib/` |
| `drakkar_scan` | the MITRE ATT&CK for Mobile detections from the rule engine |

One tool per mode, not a generic "run drakkar with these arguments". A generic
tool cannot have a whitelist: an args array *is* a command line, and nothing would
then separate `--diff-ngram`, which exists, from `--diff-json`, which does not.

Two tools cover several modes — `drakkar_resources` and `drakkar_assets` — and
only because Drakkar itself dispatches each as a single branch with a single
output shape. The selector is a closed enumeration, so the whitelist still holds.
The three inventories are *not* merged despite sharing a branch upstream: their
report shapes have no field in common, and each carries a different caveat that
belongs in its own description. A description covering three semantics warns
about none of them.

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

## The answer

Every tool returns the same envelope:

| Field | What it holds |
|---|---|
| `drakkar` | which Drakkar, the exact argv, the exit code, the duration, whether it timed out |
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
declared preview, and the whole report stays where Drakkar wrote it. Nothing is
ever cut without `truncated` saying so.

`groups` and `failed` stay inline for `drakkar_diff_matrix` against that rule:
they *are* the answer rather than the appendix, and a sample that could not be
read must not be quietly absent.

**stderr is never discarded, including on a zero exit code.** A `2>/dev/null` on a
sweep once hid failures and made a counting gap read as a regression. The
`[FAIL]`/`[PANIC]` counts are how many entries are missing from the numbers above
them, and they are reported as such.

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

## Layout

```
cmd/mcp-drakkar/      the -version flag, startup diagnostics, stdio transport
internal/drakkar/     the flag whitelist, the argv builder, the runner, the stderr
                      marker parser, the TSV parsers
internal/service/     one mode to one answer: output directory, head/tail split,
                      declared truncation, report writing
internal/mcptools/    the 29 tools and their typed inputs
internal/version/     what the server declares about itself
```

**No test invokes `drakkar`.** The whitelist is tested on the argv it produces,
the TSV parsers on fixtures, the head/tail split on decoded reports, the output
directory on a temporary directory, and the tool registration over an in-memory
MCP transport. So CI needs no Rust toolchain, no samples, and no macOS.

## Releases

Tag `vX.Y.Z`. The workflow refuses a tag that disagrees with `Version` in
`internal/version/version.go` — which is why that constant is declared in the
source rather than injected at link time: a version that only ever comes from
`-ldflags` can never disagree with the tag.

Each release carries one bare binary per target — `mcp-drakkar-darwin-arm64`,
`mcp-drakkar-linux-amd64`, `mcp-drakkar-linux-arm64` — downloadable as-is, with
nothing to unpack. Each comes with a `checksums-<target>.txt` holding its full
SHA-256, never abbreviated.

Nothing travels alongside the binary, so the binary answers for itself:

```
$ mcp-drakkar -version
mcp-drakkar 0.10.0
commit:         <the full commit, injected at link time>
target:         darwin/arm64
go:             go1.27.1
drakkar tested: 0.5.0 (693379987c5cd9f8b2815510e7904b82b6fa040a)
```

Only the commit is injected. `Version` and `DrakkarTested` are constants in
`internal/version`, and the target and Go version come from the runtime — so the
release workflow never has to restate a value that lives in the code.

No Docker, no published `go install` path.

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
