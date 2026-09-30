package drakkar

// The flag table mirrors the clap `Cli` struct of drakkar/src/main.rs at
// 9f2adda, and it is the whitelist: Args refuses any name absent from it, so a
// flag this table does not know cannot reach the command line. A parameter that
// maps to no known flag is an error, never a passthrough.
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
