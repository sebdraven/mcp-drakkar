// Command mcp-drakkar serves Drakkar over MCP: one tool per analysis mode, typed
// paths and a flag whitelist instead of a shell command line.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-drakkar/internal/corpus"
	"github.com/sebdraven/mcp-drakkar/internal/drakkar"
	"github.com/sebdraven/mcp-drakkar/internal/mcptools"
	"github.com/sebdraven/mcp-drakkar/internal/service"
	"github.com/sebdraven/mcp-drakkar/internal/version"
)

func main() {
	var (
		corpusDirs = flag.String("corpus", os.Getenv(corpus.EnvCorpus),
			"directories holding the samples, separated by the list separator (env "+corpus.EnvCorpus+"); nothing outside them is ever read")
		reportsDir = flag.String("reports", os.Getenv(corpus.EnvReports),
			"directory this server may write reports and extracted files into (env "+corpus.EnvReports+"); nothing is written outside it")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("%s (commit %s, built against drakkar %s)\n", version.Version, version.Commit, version.DrakkarTested)
		return
	}

	scope := corpus.New(filepath.SplitList(*corpusDirs), *reportsDir)
	svc := service.New(scope, service.DefaultTimeouts().FromEnv())

	// Logs go to stderr: stdout is the MCP transport. None of this is fatal — a
	// client can call drakkar_version to see the same picture, and telling it
	// there beats dying before the client can ask.
	if path, err := drakkar.NewRunner("").Lookup(); err != nil {
		log.Printf("drakkar is not callable, so every analysis tool will refuse: %v", err)
	} else {
		log.Printf("drakkar: %s", path)
	}
	if roots := scope.Roots(); len(roots) == 0 {
		log.Printf("no corpus directory: set %s, or pass -corpus; every tool that takes a path will refuse", corpus.EnvCorpus)
	} else {
		log.Printf("corpus: %v", roots)
	}
	for _, bad := range scope.BadRoots() {
		log.Printf("corpus directory configured but unusable: %s", bad)
	}
	if reports, err := scope.ReportsDir(); err != nil {
		log.Printf("no reports directory: %v", err)
	} else {
		log.Printf("reports: %s", reports)
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
