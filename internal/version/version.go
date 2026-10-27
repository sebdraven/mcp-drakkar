// Package version holds what this server declares about itself.
package version

// Version is declared here rather than injected at link time, so that the
// release workflow has something to compare the tag against. A version that
// only ever comes from -ldflags can never disagree with the tag.
const Version = "0.4.0"

// DrakkarTested names the Drakkar the tool surface was written against. A
// version number can stay put across many commits, so the commit is the
// discriminating half — and it is written whole, like every other hash this
// server reports: an abbreviation is a value nobody can check out.
//
// A constant here rather than a -ldflags injection for the same reason as
// Version: injecting it would mean the release workflow had to know a value that
// lives in the code.
const DrakkarTested = "0.2.0 (01eee3b6b8acf75bb15dd90e2ee5e301c1f90d21)"

// Commit is injected at link time by the release workflow.
var Commit = "unknown"
