// Package version holds what this server declares about itself.
package version

// Version is declared here rather than injected at link time, so that the
// release workflow has something to compare the tag against. A version that
// only ever comes from -ldflags can never disagree with the tag.
const Version = "0.1.0"

// DrakkarTested names the Drakkar the tool surface was written against. Drakkar
// has been at 0.1.0 for a while, so the commit is the discriminating half.
const DrakkarTested = "0.1.0 (9f2adda)"

// Commit is injected at link time by the release workflow.
var Commit = "unknown"
