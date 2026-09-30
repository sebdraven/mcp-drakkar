package mcptools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-drakkar/internal/service"
)

// The expected surface, written out rather than counted, so that adding or losing
// a tool is a deliberate edit here and not a silent change in behaviour.
var wantTools = []string{
	"drakkar_api_surface",
	"drakkar_assets",
	"drakkar_cert",
	"drakkar_dating",
	"drakkar_diff_dex",
	"drakkar_diff_explain",
	"drakkar_diff_matrix",
	"drakkar_diff_strings",
	"drakkar_disasm",
	"drakkar_dyn_entrypoints",
	"drakkar_extract_entry",
	"drakkar_extract_libs",
	"drakkar_legend",
	"drakkar_list_entries",
	"drakkar_manifest",
	"drakkar_native_arch",
	"drakkar_orphan_audit",
	"drakkar_probe_api",
	"drakkar_reflection_inputs",
	"drakkar_resources",
	"drakkar_scan",
	"drakkar_strings",
	"drakkar_version",
}

// connect registers the tools against a real server and lists them over an
// in-memory transport. It runs no drakkar: nothing here leaves the process.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "drakkar",
		Version: "test",
	}, &mcp.ServerOptions{
		Instructions: Instructions,
	})
	// AddTool panics when a schema cannot be inferred from an input or output
	// type, which would leave the server dead on arrival. Registering here is what
	// catches that before a release rather than on a client's first connection.
	Register(server, service.New(service.DefaultTimeouts()))

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	return clientSession
}

func listTools(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	got := map[string]*mcp.Tool{}
	for tool, err := range cs.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := got[tool.Name]; dup {
			t.Errorf("tool %q is registered twice", tool.Name)
		}
		got[tool.Name] = tool
	}
	return got
}

func TestEveryToolIsRegisteredWithASchema(t *testing.T) {
	got := listTools(t, connect(t))

	for _, name := range wantTools {
		tool, ok := got[name]
		if !ok {
			t.Errorf("tool %q is missing", name)
			continue
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has no input schema", name)
		}
		if len(tool.Description) < 80 {
			t.Errorf("tool %q has a description of %d characters; it is where the caveats live", name, len(tool.Description))
		}
	}
	if len(got) != len(wantTools) {
		for name := range got {
			if !contains(wantTools, name) {
				t.Errorf("unexpected tool %q", name)
			}
		}
		t.Errorf("registered %d tools, expected %d", len(got), len(wantTools))
	}
}

func TestToolNamesAreNamespaced(t *testing.T) {
	for name := range listTools(t, connect(t)) {
		if !strings.HasPrefix(name, "drakkar_") {
			t.Errorf("tool %q is not namespaced", name)
		}
	}
}

func TestInstructionsStateTheEnvelopeAndThePathRules(t *testing.T) {
	// A caller that never reads stderr is the failure mode this server exists to
	// remove, so the contract has to be stated where every client sees it. And a
	// caller that passes a relative path has to be told before it does.
	for _, want := range []string{
		"stderr",
		"report_path",
		"tails",
		"truncated",
		"absolute",
		"out_dir",
		"never builds",
		"drakkar_version",
	} {
		if !strings.Contains(Instructions, want) {
			t.Errorf("the instructions do not mention %q", want)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
