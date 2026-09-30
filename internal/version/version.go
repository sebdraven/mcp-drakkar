// Package version holds what this server declares about itself.
package version

// Version is declared here rather than injected at link time, so that the
// release workflow has something to compare the tag against. A version that
// only ever comes from -ldflags can never disagree with the tag.
const Version = "0.3.0"

// DrakkarTested names the Drakkar the tool surface was written against. Drakkar
// has been at 0.1.0 for a while, so the commit is the discriminating half — and
// it is written whole, like every other hash this server reports: an
// abbreviation is a value nobody can check out.
//
// A constant here rather than a -ldflags injection for the same reason as
// Version: injecting it would mean the release workflow had to know a value that
// lives in the code.
const DrakkarTested = "0.1.0 (f5237b9573ed85307d0d0f404d8a03a7312e9fdc)"

// Commit is injected at link time by the release workflow.
var Commit = "unknown"
