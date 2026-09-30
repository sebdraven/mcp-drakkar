// Command mcp-drakkar serves Drakkar over MCP: one tool per analysis mode, typed
// paths and a flag whitelist instead of a shell command line.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"runtime"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
	"github.com/sebdraven/mcp-drakkar/internal/mcptools"
	"github.com/sebdraven/mcp-drakkar/internal/service"
	"github.com/sebdraven/mcp-drakkar/internal/version"
)

func main() {
	// Nothing to configure: the paths to analyse are tool parameters, given per
	// call, and so is where the output goes.
	showVer := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVer {
		// Releases publish bare binaries, so nothing travels alongside to say what
		// this one is. It has to answer that itself: the commit is injected at link
		// time, the rest the binary already knows. Never abbreviated — an artefact
		// that cannot be traced to an exact tree is not evidence of anything.
		fmt.Printf("mcp-drakkar %s\n", version.Version)
		fmt.Printf("commit:         %s\n", version.Commit)
		fmt.Printf("target:         %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("go:             %s\n", runtime.Version())
		fmt.Printf("drakkar tested: %s\n", version.DrakkarTested)
		return
	}

	svc := service.New(service.DefaultTimeouts().FromEnv())

	// Logs go to stderr: stdout is the MCP transport. Not fatal — a client can
	// call drakkar_version to see the same picture, and telling it there beats
	// dying before the client can ask.
	if path, err := drakkar.NewRunner("").Lookup(); err != nil {
		log.Printf("drakkar is not callable, so every analysis tool will refuse: %v", err)
	} else {
		log.Printf("drakkar: %s", path)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "drakkar",
		Version: version.Version,
	}, &mcp.ServerOptions{
		Instructions: mcptools.Instructions,
	})
	mcptools.Register(server, svc)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server: %v", err)
	}
}
