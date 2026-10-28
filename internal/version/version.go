// Package version holds what this server declares about itself.
package version

// Version is declared here rather than injected at link time, so that the
// release workflow has something to compare the tag against. A version that
// only ever comes from -ldflags can never disagree with the tag.
const Version = "0.5.0"

// DrakkarTested names the Drakkar the tool surface was written against. A
// version number can stay put across many commits, so the commit is the
// discriminating half — and it is written whole, like every other hash this
// server reports: an abbreviation is a value nobody can check out.
//
// A constant here rather than a -ldflags injection for the same reason as
// Version: injecting it would mean the release workflow had to know a value that
// lives in the code.
const DrakkarTested = "0.2.2 (2ea2bc75f89709bd9de4fc69b05b408ab8581de3)"

// Commit is injected at link time by the release workflow.
var Commit = "unknown"
