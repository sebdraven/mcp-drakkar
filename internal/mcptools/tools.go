// Package mcptools exposes Drakkar over MCP as one tool per mode.
//
// One tool per mode rather than a generic "run drakkar with these arguments" is
// the whole design. A generic tool cannot have a whitelist: an args array is a
// command line, and nothing would then separate --diff-ngram, which exists, from
// --diff-json, which does not. Here the flag that does not exist is not refused,
// it is inexpressible.
//
// The descriptions carry the caveats a model gets wrong otherwise: which measure
// a mode actually reports, what its metric does not mean, and where a default
// lives. Defaults are never restated in a description either — a number copied
// here would drift from Drakkar just as surely as one copied into the code.
package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-drakkar/internal/service"
)

// Instructions is handed to the client once, so that the envelope contract and
// the path rules are not repeated in twenty-eight descriptions.
const Instructions = `Drakkar is a static analysis engine for Android APKs and raw DEX files. Every tool here runs the drakkar binary found on PATH; this server never builds, installs or downloads it.

Paths are parameters, given per call, and must be absolute — a relative one would be resolved against a working directory nobody chose. There is nothing to configure and no directory to declare in advance.

Output goes where out_dir says. Omitted, the server makes a fresh directory under the system temp directory and returns its path in report_path, so a report never lands somewhere unpredictable. Call drakkar_version to see which Drakkar is in use and where that fallback is.

Every tool answers with the same envelope:
  drakkar     which Drakkar, the exact argv, the exit code, the duration, whether it timed out
  stderr      the whole of stderr verbatim, plus counts of Drakkar's [OK]/[FAIL]/[PANIC]/[AVERT] markers and the named failures
  result      the scalar head of the report: the measurement itself
  tails       one entry per unbounded array, each with total, returned, truncated and a preview
  rows        for the modes whose only output is TSV: the header as read, a declared preview, and the count of malformed lines
  report_path the complete report on disk
  notes       anything that changes how the numbers should be read

Read stderr and notes before the numbers. A non-zero exit code or a non-zero failure count means entries are missing from the counts, and a truncated tail means the array was longer than the preview.

Flags with a Drakkar default are omitted unless you set them, so Drakkar decides. SHA-256 values are never truncated, here or anywhere in the output.`

type registry struct{ svc *service.Service }

func Register(s *mcp.Server, svc *service.Service) {
	r := &registry{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_version",
		Description: "Report which Drakkar is on the PATH, which Drakkar this server was written against, the timeouts in force, and where output lands when a call names no out_dir. " +
			"Call it first when something refuses, and call it to date a measurement: nothing else records which engine produced a number.",
	}, r.version)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_legend",
		Description: "Print Drakkar's own legend for a mode: the labels it emits and the rules it derives them by. " +
			"These texts are where a metric's limits are stated — that orphan means unreferenced from code and not unused, that the near-class threshold is a parameter of the tool and not a published empirical value — so read the legend before interpreting a number from the matching mode. " +
			"Reads no sample.",
	}, r.legend)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_manifest",
		Description: "Inventory the AndroidManifest.xml: permissions, components, intent filters and the entry points derived from them. " +
			"Works on one APK or, with directory, over a whole batch, writing one report per sample. " +
			"Derived entry points are the ones declared in the manifest; components reached only at runtime are drakkar_dyn_entrypoints, not this.",
	}, r.manifest)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_cert",
		Description: "Inventory the signature: v1/v2/v3/v3.1 schemes and the X.509 certificates, with distinguished names, validity windows and fingerprints. " +
			"Works on one APK or over a batch. " +
			"A shared certificate ties two samples to the same signer; it says nothing on its own about shared code, which is what the diff tools measure.",
	}, r.cert)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_dating",
		Description: "Raw dating indicators: signature dates, build-chain floors (DEX format, schemes, compileSdk, library versions), archive timestamps, date literals in the code, API targets. " +
			"No date is ever estimated and no single figure is produced — these are the indicators, and reconciling them is the reader's job. " +
			"Read drakkar_legend with topic dating before drawing a timeline from them.",
	}, r.dating)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_native",
		Description: "Static analysis of every ELF in the APK, found by content (lib/, assets/, res/raw/, elsewhere): sections, entropy, needed libraries, classified imports and strings, Java_* exports, JNINativeMethod tables rebuilt through relative relocations, and the binding of DEX native methods to them (static, registered, registered_ambiguous, declared_unbound, native_unclaimed). " +
			"No disassembly, no execution. Use it for the Java↔native boundary; drakkar_native_arch only reads ELF headers under lib/. " +
			"The head is the summary; elfs, binding (sorted by status, then java, cut at max_rows) and errors are tails, and sections, imports and strings stay in report_path. " +
			"It extracts nothing: drakkar_extract_libs remains the tool for getting the files themselves. One APK at a time.",
	}, r.native)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_native_arch",
		Description: "Audit the native libraries' architecture: ABI, word size and machine type of each .so, read from the ELF headers in memory. " +
			"Covers lib/ only; a packer hiding a .so elsewhere in the archive shows up through drakkar_assets or drakkar_extract_libs. " +
			"Text output, one APK at a time.",
	}, r.nativeArch)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_strings",
		Description: "Read the DEX string pool, whole or filtered by case-insensitive substring. Accepts an APK or a raw DEX, one sample or a whole directory. " +
			"This is the literal pool, so it holds what instructions never write: the value of a static final String lives here and nowhere else. " +
			"stderr reports how many strings were read against how many the header declared, and how many were unreadable — a gap there means a damaged DEX, not an absence of strings.",
	}, r.strings)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_disasm",
		Description: "Disassemble the classes whose Dalvik descriptor matches a pattern, with indexed operands resolved to plain strings, types, methods and fields. " +
			"This is the complement to drakkar_diff_dex, which is blind to operands. It is not a decompiler: no control flow is reconstructed and no types are inferred. " +
			"Text output, one sample at a time, meant to be read and diffed as it stands.",
	}, r.disasm)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_decompile",
		Description: "Decompile to Java the classes whose Dalvik descriptor matches a pattern — the same case-insensitive substring selection as drakkar_disasm, every class when no pattern is given. Accepts an APK or a raw DEX recognised by content. " +
			"The Java comes from dex-decompiler, a young decompiler: when a line matters, check it against drakkar_disasm, which shows the bytecode with operands resolved. " +
			"A class headed `// repli méthode par méthode` is one where decompile_class failed: what follows is the per-method rendering, without fields, imports or inner classes, and stderr counts them. " +
			"The whole Java is written to decompiled.java; only max_chars of it come back inline. Needs Drakkar 0.2.0.",
	}, r.decompile)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_bundle",
		Description: "Write the bundle of one APK or raw DEX to out_dir/<sha256 of the input>/: manifest, signature, dating, rule matches, string pool and static values, dynamic entry points, and every class disassembled and decompiled, libraries included, one set of files per class id. " +
			"The answer is bundle.json whole, the count and a preview of errors.json, and the classes of index.json counted by origin, decompile_status and class_java; read the classes themselves with drakkar_bundle_index, then drakkar_bundle_class. " +
			"out_dir is required, and an existing bundle of the same input is refused unless overwrite is set. Like drakkar_scan it loads the MITRE catalogue, so a first call after a cache miss reaches the network. A part that fails is null in its file and recorded in errors.json rather than stopping the bundle. " +
			"drakkar_legend with topic bundle defines every file and field. Needs Drakkar 0.2.0.",
	}, r.bundle)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_bundle_index",
		Description: "List the classes of a bundle written by drakkar_bundle, from its index.json, filtered by origin, decompile_status, class_java, package prefix and whether a rule cites the class directly. Runs no analysis. " +
			"This is how to choose what to read next with drakkar_bundle_class. Prioritise with rules_direct: a rule's evidence names the class's descriptor, or the class owns the immediate caller of the API in an evidence path. " +
			"rules_path does not prioritise: a path starts at an entry point or a rule's pivot, so it cites every class traversed on the way. " +
			"origin app is over-inclusive — a library missing from Drakkar's exclusion list, or renamed by ProGuard, counts as app.",
	}, r.bundleIndex)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_bundle_class",
		Description: "Read one class of a bundle written by drakkar_bundle, by id or by exact descriptor, without running an analysis: its index.json entry, then classes/<id>.class.java (the whole class, absent when decompile_class failed), classes/<id>.java (method by method, the file java_lines points into), classes/<id>.dasm (the bytecode, in drakkar_disasm's format) and classes/<id>.json (one record per method: status, fallback markers, line spans). " +
			"Each part is cut at max_chars and names its full file; the errors.json entries for the class come with it. " +
			"Read the Java as an aid from a young decompiler and the .dasm as the reference.",
	}, r.bundleClass)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_dyn_entrypoints",
		Description: "Find the component classes reached other than by a manifest declaration: registerReceiver, startActivity, startService, bindService, new Intent(ctx, X.class), setClass, setComponent, Class.forName. " +
			"Accepts an APK or a raw DEX recognised by content, which is what lets you pass the unpacked DEX of a packed sample. " +
			"Unresolved call sites are reported alongside the resolved ones, with the reason they could not be resolved: they are not failures, they are the part the measure does not reach.",
	}, r.dynEntrypoints)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_reflection_inputs",
		Description: "Classify where the NAME of each reflection target comes from: const, decrypt-const, runtime, param, indirect, unknown, over Method.invoke, Class.forName, getMethod and getDeclaredMethod. " +
			"The decrypt-const to runtime ratio is what says whether a replayable deobfuscation pass is worth building. " +
			"Every category is reported even at zero, so counts stay comparable between samples.",
	}, r.reflectionInputs)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_api_surface",
		Description: "Read the network protocol the sample DECLARES: the HTTP verb and route template of each Retrofit method, the names its @Path, @Query, @Body, @Header, @Field and @Part parameters bind to, and the wire key of each Gson @SerializedName field. " +
			"This reads annotations and no instruction at all, so it sees what no bytecode sweep reaches — on a Retrofit client the routes exist only here — and misses what is built at runtime, which is drakkar_strings' half of the job. " +
			"An empty answer means not Retrofit, or Retrofit repackaged under another package name; it never means the sample has no HTTP routes. Weigh other_annotations against annotations_seen in the head to tell those two apart.",
	}, r.apiSurface)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_orphan_audit",
		Description: "Partition the methods unreachable from the entry points into weakly connected components and flag those containing System.loadLibrary. " +
			"Root saturation is measured in four stages — manifest, then dynamic, then UI handlers, then clinit — and only what survives the last stage is the interpretable residue. " +
			"Without a manifest the roots are heuristic, which the report states as roots_mode: a heuristic measure is not comparable with a manifest one.",
	}, r.orphanAudit)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_probe_api",
		Description: "Ask whether one precise API is a node of the call graph and whether it is reachable from the roots, with the paths as evidence. " +
			"Takes a substring of class->name, for example System;->loadLibrary. " +
			"Use it to check a single hypothesis; use drakkar_orphan_audit for the shape of the whole graph.",
	}, r.probeAPI)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_diff_dex",
		Description: "Compare two DEX or APK by opcode fingerprint, to answer whether they come from the same source tree despite package renaming and ProGuard: only the mnemonic sequence of each method is kept. " +
			"It is blind to operands by construction, so two builds differing only in a C2 endpoint look identical here — pair it with drakkar_diff_explain and drakkar_diff_strings. " +
			"Classes paired by fingerprint alone with different names are real renamings, but that bucket is also where POJOs with identical fingerprints can be mismatched: a high count there without an expected renaming deserves suspicion.",
	}, r.diffDex)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_diff_explain",
		Description: "Compare the resolved operands of methods that share an opcode fingerprint, index by index, and categorise each divergence: string, method target, type, real field, renamed field. " +
			"This closes drakkar_diff_dex's blind spot. Between two separately obfuscated batches, pass normalize or every operand diverges on the namespace alone and the output is noise. " +
			"Static field values are compared by name and counted, but unpaired ones are never reported as divergences, because a field-name remapping would produce them in bulk.",
	}, r.diffExplain)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_diff_strings",
		Description: "Compare the string pools of two DEX or APK, with the divergences classified by nature. " +
			"Indispensable next to drakkar_diff_explain: a static final String is not written by any instruction — its value lives in encoded_static_values — so instruction diffs are blind to it, C2 endpoints included. The pool holds everything. " +
			"literals_only masks the structural noise of the DEX format; normalize with brand=BRAND keeps only what differs beyond the name.",
	}, r.diffStrings)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_diff_matrix",
		Description: "Score every pair in a directory of APKs or DEX against every other, then group by single linkage. Each sample is parsed once and the comparisons run on in-memory sets, which is what makes all-against-all tractable over a corpus. " +
			"Both metrics are always computed; metric selects which one drives the matrix and the grouping — opcodes for same engine, strings for same constants. " +
			"The result is n-squared: the pairs come back as a declared preview of the ranking, and the whole matrix stays on disk. Samples that could not be read are named in failed rather than being quietly absent.",
	}, r.diffMatrix)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_resources",
		Description: "Read resources.arsc: resolve names or identifiers, dump the table, join DEX constants to the resource entries they really designate (xref), or list the resources no DEX constant references (orphans). " +
			"orphans means unreferenced FROM THE CODE, never unused: a resource cited by a layout, a style, a theme or the manifest appears here and is perfectly used. " +
			"xref reports one row per usage with its origin and consumer, and its end-of-pass summary is what lets you bound the false positive rate.",
	}, r.resources)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_assets",
		Description: "Inventory, fingerprint or extract the assets/ entries: path, sizes, declared method, whole SHA-256, type sniffed from the leading bytes rather than the extension, and entropy. " +
			"Falls back to a tolerant reader when the zip crate refuses the archive, which is what keeps tampered APKs from coming back with no assets at all. " +
			"Filter by hash to pivot on a known payload; the fingerprint is only emitted when it covers every asset, and says why when it does not. An asset that is itself a ZIP, APK or DEX is typed and written as-is, never unpacked recursively.",
	}, r.assets)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_list_entries",
		Description: "List every entry path in the archive. Nothing is extracted and nothing is written. " +
			"This is how you find what to pass to drakkar_extract_entry, and it is the tool for looking around a packed APK by hand.",
	}, r.listEntries)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_extract_entry",
		Description: "Extract the archive entries matching a pattern into this call's report directory: an exact path, a glob, or a substring, case-insensitive. " +
			"Only the requested entries are read — the archive is never unpacked whole. The SHA-256 reported is that of the decompressed content, and the type is sniffed from the bytes. " +
			"For an embedded plugin APK under res/raw, or a packer payload under assets/.",
	}, r.extractEntry)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_extract_libs",
		Description: "Extract every native ELF .so from the archive into this call's report directory, including the ones outside lib/ where packers put them. " +
			"Use it when drakkar_native_arch, which reads lib/ only, reports fewer libraries than the sample seems to carry.",
	}, r.extractLibs)

	mcp.AddTool(s, &mcp.Tool{
		Name: "drakkar_scan",
		Description: "Run the rule engine and return the MITRE ATT&CK for Mobile detections. One APK, or a whole directory with one report per sample. " +
			"Unlike every other tool here but drakkar_bundle, this one loads the MITRE catalogue, so a first call after a cache miss reaches the network; refresh forces that download. " +
			"It is the heaviest mode: the inventory and measurement tools answer most questions without building the call graph.",
	}, r.scan)
}

func (r *registry) version(ctx context.Context, _ *mcp.CallToolRequest, in service.VersionInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Version(ctx, in)
	return nil, env, err
}

func (r *registry) legend(ctx context.Context, _ *mcp.CallToolRequest, in service.LegendInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Legend(ctx, in)
	return nil, env, err
}

func (r *registry) manifest(ctx context.Context, _ *mcp.CallToolRequest, in service.InventoryInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Manifest(ctx, in)
	return nil, env, err
}

func (r *registry) cert(ctx context.Context, _ *mcp.CallToolRequest, in service.InventoryInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Cert(ctx, in)
	return nil, env, err
}

func (r *registry) dating(ctx context.Context, _ *mcp.CallToolRequest, in service.InventoryInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Dating(ctx, in)
	return nil, env, err
}

func (r *registry) native(ctx context.Context, _ *mcp.CallToolRequest, in service.NativeInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Native(ctx, in)
	return nil, env, err
}

func (r *registry) nativeArch(ctx context.Context, _ *mcp.CallToolRequest, in service.NativeArchInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.NativeArch(ctx, in)
	return nil, env, err
}

func (r *registry) strings(ctx context.Context, _ *mcp.CallToolRequest, in service.StringsInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Strings(ctx, in)
	return nil, env, err
}

func (r *registry) disasm(ctx context.Context, _ *mcp.CallToolRequest, in service.DisasmInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Disasm(ctx, in)
	return nil, env, err
}

func (r *registry) decompile(ctx context.Context, _ *mcp.CallToolRequest, in service.DecompileInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Decompile(ctx, in)
	return nil, env, err
}

func (r *registry) bundle(ctx context.Context, _ *mcp.CallToolRequest, in service.BundleInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Bundle(ctx, in)
	return nil, env, err
}

func (r *registry) bundleIndex(ctx context.Context, _ *mcp.CallToolRequest, in service.BundleIndexInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.BundleIndex(ctx, in)
	return nil, env, err
}

func (r *registry) bundleClass(ctx context.Context, _ *mcp.CallToolRequest, in service.BundleClassInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.BundleClass(ctx, in)
	return nil, env, err
}

func (r *registry) dynEntrypoints(ctx context.Context, _ *mcp.CallToolRequest, in service.DynEntrypointsInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.DynEntrypoints(ctx, in)
	return nil, env, err
}

func (r *registry) reflectionInputs(ctx context.Context, _ *mcp.CallToolRequest, in service.ReflectionInputsInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.ReflectionInputs(ctx, in)
	return nil, env, err
}

func (r *registry) apiSurface(ctx context.Context, _ *mcp.CallToolRequest, in service.APISurfaceInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.APISurface(ctx, in)
	return nil, env, err
}

func (r *registry) orphanAudit(ctx context.Context, _ *mcp.CallToolRequest, in service.OrphanAuditInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.OrphanAudit(ctx, in)
	return nil, env, err
}

func (r *registry) probeAPI(ctx context.Context, _ *mcp.CallToolRequest, in service.ProbeInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Probe(ctx, in)
	return nil, env, err
}

func (r *registry) diffDex(ctx context.Context, _ *mcp.CallToolRequest, in service.DiffDexInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.DiffDex(ctx, in)
	return nil, env, err
}

func (r *registry) diffExplain(ctx context.Context, _ *mcp.CallToolRequest, in service.DiffExplainInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.DiffExplain(ctx, in)
	return nil, env, err
}

func (r *registry) diffStrings(ctx context.Context, _ *mcp.CallToolRequest, in service.DiffStringsInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.DiffStrings(ctx, in)
	return nil, env, err
}

func (r *registry) diffMatrix(ctx context.Context, _ *mcp.CallToolRequest, in service.DiffMatrixInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.DiffMatrix(ctx, in)
	return nil, env, err
}

func (r *registry) resources(ctx context.Context, _ *mcp.CallToolRequest, in service.ResourcesInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Resources(ctx, in)
	return nil, env, err
}

func (r *registry) assets(ctx context.Context, _ *mcp.CallToolRequest, in service.AssetsInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Assets(ctx, in)
	return nil, env, err
}

func (r *registry) listEntries(ctx context.Context, _ *mcp.CallToolRequest, in service.ListEntriesInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.ListEntries(ctx, in)
	return nil, env, err
}

func (r *registry) extractEntry(ctx context.Context, _ *mcp.CallToolRequest, in service.ExtractEntryInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.ExtractEntry(ctx, in)
	return nil, env, err
}

func (r *registry) extractLibs(ctx context.Context, _ *mcp.CallToolRequest, in service.ExtractLibsInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.ExtractLibs(ctx, in)
	return nil, env, err
}

func (r *registry) scan(ctx context.Context, _ *mcp.CallToolRequest, in service.ScanInput) (*mcp.CallToolResult, *service.Envelope, error) {
	env, err := r.svc.Scan(ctx, in)
	return nil, env, err
}
