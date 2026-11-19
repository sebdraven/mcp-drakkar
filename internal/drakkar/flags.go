package drakkar

// The flag table mirrors the clap `Cli` struct of drakkar/src/main.rs,
// checked against the 0.8.0 source named by version.DrakkarTested.
// It is the whitelist: Args
// refuses any name absent from it, so a flag this table does not know cannot
// reach the command line. A parameter that maps to no known flag is an error,
// never a passthrough.
//
// Deliberately absent, and asserted absent by a test: --enrich, --enrich-input,
// --cache, --rate, --force. Mass enrichment — cached, rate-limited, over a list
// of hashes — is a function this server declines to expose, so that it never
// has to hold VT_API_KEY or KOODOUS_TOKEN. --help is absent too.

type kind int

const (
	// switchFlag is a bare boolean: --manifest
	switchFlag kind = iota
	// valueFlag takes exactly one value, emitted as --name=value
	valueFlag
	// multiFlag is repeatable, emitted as one --name=value per value
	multiFlag
	// pairFlag takes exactly two operands, emitted as three argv items
	pairFlag
	// optionalMultiFlag takes zero or more values: bare, or repeated --name=value
	optionalMultiFlag
	// optionalValueFlag takes zero or one value: bare, or --name=value
	optionalValueFlag
)

// known is built by assignment rather than as a literal so that no column
// alignment is implied by the source layout.
var known = map[string]kind{}

// withheld names Drakkar flags this server knows and refuses to emit. Kept as
// data so the reason is testable, not merely written down.
var withheld = map[string]string{}

func init() {
	// Batch and output plumbing
	known["--bulk"] = valueFlag
	known["--out"] = valueFlag
	known["--recursive"] = switchFlag
	known["--overwrite"] = switchFlag
	known["--jobs"] = valueFlag
	known["--rules"] = valueFlag
	known["--refresh"] = switchFlag
	known["--color"] = valueFlag
	known["--format"] = valueFlag
	known["--json-out"] = valueFlag
	known["--legend"] = switchFlag
	known["--version"] = switchFlag
	known["--export-graph"] = valueFlag

	// Inventory
	known["--manifest"] = switchFlag
	known["--cert"] = switchFlag
	known["--dating"] = switchFlag

	// Native libraries and archive entries
	known["--native-arch"] = switchFlag
	known["--native"] = switchFlag
	// Native disassembly and its bounds.
	known["--native-disasm"] = switchFlag
	known["--disasm-depth"] = valueFlag
	known["--disasm-max-insns"] = valueFlag
	known["--native-dex"] = multiFlag
	known["--native-listing"] = multiFlag
	// Symbolic execution and its options.
	// Drakkar splits the list options on commas; they go as one joined value.
	known["--native-symex"] = valueFlag
	known["--native-symex-watch"] = valueFlag
	known["--native-symex-peek"] = valueFlag
	known["--native-symex-entry"] = valueFlag
	known["--native-symex-depth"] = valueFlag
	known["--native-symex-max-insns"] = valueFlag
	known["--native-symex-max-paths"] = valueFlag
	known["--native-symex-fragment-max"] = valueFlag
	known["--native-symex-callee-forks"] = valueFlag
	known["--native-symex-refine"] = valueFlag
	known["--native-symex-follow"] = valueFlag
	known["--native-symex-undirected"] = switchFlag
	// Native references and their cap.
	// Drakkar repeats --native-xrefs; the server passes one spec.
	known["--native-xrefs"] = valueFlag
	known["--native-xrefs-max"] = valueFlag
	// Native words and method tables. Drakkar repeats --native-words; the server passes one spec.
	// Drakkar splits the address lists on commas; they go as one joined value.
	known["--native-words"] = valueFlag
	known["--native-vtables"] = valueFlag
	known["--native-vtables-fn"] = valueFlag
	known["--native-vtables-slot"] = valueFlag
	known["--native-vtables-size"] = valueFlag
	known["--native-vtables-at"] = valueFlag
	known["--native-vtables-max"] = valueFlag
	known["--native-vtables-refs"] = switchFlag
	// Native function labels and their options.
	// Drakkar splits --native-labels-fn and --native-labels-match on commas.
	known["--native-labels"] = valueFlag
	known["--native-labels-fn"] = valueFlag
	known["--native-labels-match"] = valueFlag
	known["--native-labels-max"] = valueFlag
	known["--native-labels-strings-max"] = valueFlag
	known["--native-labels-fragment-fanout"] = valueFlag
	// Native field accesses, slices, async graphs and deserializer fields.
	// Drakkar splits the list
	// options on commas; they go as one joined value, always with '='.
	known["--native-find"] = valueFlag
	known["--native-find-off"] = valueFlag
	known["--native-find-access"] = valueFlag
	known["--native-find-size"] = valueFlag
	known["--native-find-base"] = valueFlag
	known["--native-find-in"] = valueFlag
	known["--native-find-max"] = valueFlag
	known["--native-slice"] = valueFlag
	known["--native-slice-at"] = valueFlag
	known["--native-slice-depth"] = valueFlag
	known["--native-slice-follow"] = valueFlag
	known["--native-slice-max-steps"] = valueFlag
	known["--native-slice-max-sources"] = valueFlag
	known["--native-async-graph"] = valueFlag
	known["--native-async-from"] = valueFlag
	known["--native-async-to"] = valueFlag
	known["--native-async-path"] = valueFlag
	known["--native-async-depth"] = valueFlag
	known["--native-async-max"] = valueFlag
	known["--native-async-kinds"] = valueFlag
	known["--native-fields"] = valueFlag
	known["--native-fields-fn"] = valueFlag
	known["--native-fields-name"] = valueFlag
	known["--native-fields-min"] = valueFlag
	known["--native-fields-fragment-fanout"] = valueFlag
	known["--native-fields-max"] = valueFlag
	// --dart-snapshot and its options: Drakkar 0.5.0
	known["--dart-snapshot"] = switchFlag
	known["--dart-max-rows"] = valueFlag
	known["--dart-calibrate"] = multiFlag
	// --native-strings and its options: Drakkar 0.6.0
	known["--native-strings"] = optionalMultiFlag
	known["--min-length"] = valueFlag
	known["--elf"] = valueFlag
	known["--xrefs"] = switchFlag
	known["--crates"] = switchFlag
	known["--extract-libs"] = switchFlag
	known["--list-entries"] = switchFlag
	known["--extract-entry"] = multiFlag

	// Assets
	known["--list-assets"] = switchFlag
	known["--extract-assets"] = valueFlag
	known["--assets-fingerprint"] = switchFlag
	known["--assets-include"] = multiFlag
	known["--assets-max-size"] = valueFlag
	known["--assets-hash"] = multiFlag
	known["--assets-hash-file"] = valueFlag
	known["--assets-hash-exclude"] = multiFlag
	known["--assets-hash-exclude-file"] = valueFlag

	// Graph and code measures
	known["--dyn-entrypoints"] = switchFlag
	known["--reflection-inputs"] = switchFlag
	known["--orphan-audit"] = switchFlag
	known["--probe"] = valueFlag
	known["--strings"] = optionalMultiFlag
	known["--disasm"] = optionalMultiFlag
	known["--disasm-normalize"] = multiFlag
	known["--api-surface"] = switchFlag

	// Decompilation and bundle, since 0.2.0
	known["--decompile"] = optionalMultiFlag
	known["--bundle"] = optionalValueFlag
	known["--archive"] = switchFlag

	// Resources
	known["--resource"] = multiFlag
	known["--resource-id"] = multiFlag
	known["--resources"] = optionalMultiFlag
	known["--resource-xref"] = switchFlag
	known["--resource-orphans"] = switchFlag

	// diff-dex
	known["--diff-dex"] = pairFlag
	known["--diff-include"] = multiFlag
	known["--diff-threshold"] = valueFlag
	known["--diff-ngram"] = valueFlag
	known["--diff-normalize"] = multiFlag

	// diff-explain
	known["--diff-explain"] = pairFlag
	known["--explain-include"] = multiFlag
	known["--explain-normalize"] = multiFlag
	known["--explain-context"] = valueFlag
	known["--explain-align-cap"] = valueFlag

	// diff-strings
	known["--diff-strings"] = pairFlag
	known["--strings-normalize"] = multiFlag
	known["--strings-literals"] = switchFlag
	known["--strings-min-len"] = valueFlag

	// diff-matrix
	known["--diff-matrix"] = valueFlag
	known["--matrix-metric"] = valueFlag
	known["--matrix-normalize"] = multiFlag
	known["--matrix-threshold"] = valueFlag
	known["--matrix-top"] = valueFlag

	withheld["--enrich"] = "mass enrichment is not exposed: the server holds no API token"
	withheld["--enrich-input"] = "only meaningful with --enrich"
	withheld["--cache"] = "only meaningful with --enrich"
	withheld["--rate"] = "only meaningful with --enrich"
	withheld["--force"] = "only meaningful with --enrich"
}
