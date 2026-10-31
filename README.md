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

Output goes wherever the call's `out_dir` says. Omitted, the server makes a fresh
directory under the system temp directory and returns its path in `report_path`.
That fallback exists for one reason: Drakkar's own `--out` defaults to `./reports`
*relative to the working directory*, which for a server started by an MCP client
is arbitrary. The server never lets that default apply — it substitutes an
absolute directory and says where it is.

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
| `drakkar_legend` | Drakkar's own legend for a mode: where a metric's limits are stated; topic `native` covers `drakkar_native`, including its disasm labels |
| `drakkar_manifest` | permissions, components, intent filters, derived entry points |
| `drakkar_cert` | signature schemes v1/v2/v3/v3.1 and the X.509 certificates |
| `drakkar_dating` | raw dating indicators — no date is ever estimated |
| `drakkar_native` | every ELF found by content, its JNI exports and tables, and the binding of DEX native methods to them; with `disasm`, the static disassembly of every JNI-bound function, `JNI_OnLoad` and the `init_array` constructors — JNIEnv calls decoded, PLT imports called, strings referenced — bounded by `disasm_depth` (0–3) and `disasm_max_insns` (1–20000), instructions left in `report.json`; each `disasm_functions` row counts its `invalid_paths` and each `elfs` row carries `invalid_paths_count` (null without `disasm` or before Drakkar 0.2.3), both defined by `drakkar_legend` topic `native` |
| `drakkar_native_arch` | ABI, word size and machine of each `.so` under `lib/` |
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
one they refuse with a message saying so. `drakkar_bundle` is the one tool whose
`out_dir` is required: the bundle is a deliverable, written to
`OUT/<sha256 of the input>/`, never to a temporary directory. The two readers run
no analysis — they read that directory, and call nothing but `drakkar --version`,
to refuse alongside the others when the Drakkar on `PATH` predates 0.2.0.

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
- **`--assets-hash-file` and `--assets-hash-exclude-file`.** The hashes pass
  inline instead, which keeps the filter visible in the `argv` the envelope
  reports rather than hidden behind a file path.
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
internal/mcptools/    the 28 tools and their typed inputs
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
mcp-drakkar 0.9.0
commit:         <the full commit, injected at link time>
target:         darwin/arm64
go:             go1.27.1
drakkar tested: 0.3.0 (b361caba436f2cbeafc01076a9e75272cf720dc4)
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
