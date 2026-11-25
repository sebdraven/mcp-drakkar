package service

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Opt-in: normal CI needs neither Drakkar nor a sample corpus.
func TestCompatibilityNative(t *testing.T) {
	bin := os.Getenv("DRAKKAR_COMPAT_BIN")
	if bin == "" {
		t.Skip("set DRAKKAR_COMPAT_BIN to an absolute Drakkar binary path")
	}
	if !filepath.IsAbs(bin) || filepath.Base(bin) != "drakkar" {
		t.Fatal("DRAKKAR_COMPAT_BIN must be absolute and named drakkar")
	}
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	s, base := testService(t)
	ctx := context.Background()
	env, err := s.Version(ctx, VersionInput{})
	if err != nil {
		t.Fatal(err)
	}
	if got := env.Result.(map[string]any)["drakkar_version"]; got != "drakkar 0.9.0" {
		t.Fatalf("expected Drakkar 0.9.0, got %v", got)
	}
	elf := compatibilityELF(t)
	check := func(t *testing.T, env *Envelope, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if !env.Drakkar.Complete || env.Tails["errors"].Total != 0 {
			t.Fatalf("native analysis failed: %+v, notes %q, stderr %+v", env.Drakkar, env.Notes, env.Stderr)
		}
	}
	t.Run("stack reload aliases", func(t *testing.T) {
		env, err := s.NativeSlice(ctx, NativeSliceInput{
			APK: elf, Function: "*@0x1000", At: []string{"0x1014:x2"},
			OutDir: filepath.Join(base, "slice"),
		})
		check(t, env, err)
		sources := env.Tails["sources"]
		if sources.Total != 2 {
			t.Fatalf("expected aliased and exact sources, got %+v", sources)
		}
		aliased, exact := false, false
		for _, item := range sources.Items {
			row := item.(map[string]any)
			aliases, _ := row["aliases"].([]any)
			if row["kind"] == "arg" && row["location"] == "x1" && len(aliases) == 1 && aliases[0] == "0x1008" {
				aliased = true
			}
			if row["kind"] == "init_mem" && row["location"] == "x0+0x10:8" && len(aliases) == 0 {
				exact = true
			}
		}
		if !aliased || !exact || !strings.Contains(strings.Join(env.Notes, "\n"), "assumed stack reload") {
			t.Fatalf("aliases or exact source lost: %+v, notes %q", sources, env.Notes)
		}
	})
	t.Run("fragment and standalone edges", func(t *testing.T) {
		one := 1
		env, err := s.NativeAsyncGraph(ctx, NativeAsyncGraphInput{
			APK: elf, From: []string{"0x1100", "0x1280"}, Depth: &one,
			OutDir: filepath.Join(base, "graph"),
		})
		check(t, env, err)
		raised, standalone := false, false
		for _, item := range env.Tails["edges"].Items {
			row := item.(map[string]any)
			if row["from"] == "0x1100" && row["to"] == "0x1240" && row["via_fragment"] == "0x1200" {
				raised = true
			}
			if row["from"] == "0x1280" && row["to"] == "0x1240" {
				_, via := row["via_fragment"]
				standalone = !via
			}
		}
		if !raised || !standalone {
			t.Fatalf("fragment or standalone edges lost: %+v", env.Tails["edges"])
		}
	})
}

// A minimal ELF64 AArch64 with symbols, generated rather than a checked-in
// executable. Instructions mirror Drakkar's stack-alias regression case.
func compatibilityELF(t *testing.T) string {
	t.Helper()
	data := make([]byte, 0x3400)
	put16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(data[at:], v) }
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(data[at:], v) }
	put64 := func(at int, v uint64) { binary.LittleEndian.PutUint64(data[at:], v) }
	copy(data, "\x7fELF\x02\x01\x01")
	put16(16, 3)   // ET_DYN
	put16(18, 183) // EM_AARCH64
	put32(20, 1)
	put64(32, 64)     // program headers
	put64(40, 0x3000) // section headers
	put16(52, 64)
	put16(54, 56)
	put16(56, 1)
	put16(58, 64)
	put16(60, 5)
	put16(62, 4)
	put32(64, 1) // PT_LOAD, R+X, identity mapping
	put32(68, 5)
	put64(96, 0x2000)
	put64(104, 0x2000)
	put64(112, 0x1000)
	type function struct {
		at   uint64
		size uint64
		name string
		code []uint32
	}
	functions := []function{
		{0x1000, 28, "alias", []uint32{0xd10083ff, 0xf90007e0, 0xf94007e9, 0xf9000921, 0xf9400802, 0x910083ff, 0xd65f03c0}},
		{0x1100, 128, "caller", []uint32{0x94000040, 0xd65f03c0}},
		{0x1200, 8, "fragment", []uint32{0x94000010, 0xd65f03c0}},
		{0x1240, 4, "target", []uint32{0xd65f03c0}},
		{0x1280, 8, "standalone", []uint32{0x97fffff0, 0xd65f03c0}},
	}
	names := "\x00"
	for i, f := range functions {
		for j, word := range f.code {
			put32(int(f.at)+4*j, word)
		}
		sym := 0x3200 + 24*(i+1)
		put32(sym, uint32(len(names)))
		data[sym+4] = 0x12 // STB_GLOBAL | STT_FUNC
		put16(sym+6, 1)
		put64(sym+8, f.at)
		put64(sym+16, f.size)
		names += f.name + "\x00"
	}
	copy(data[0x3300:], names)
	shnames := "\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
	copy(data[0x3380:], shnames)
	section := func(i int, name, kind uint32, flags, addr, offset, size, align, entry uint64, link, info uint32) {
		at := 0x3000 + 64*i
		put32(at, name)
		put32(at+4, kind)
		put64(at+8, flags)
		put64(at+16, addr)
		put64(at+24, offset)
		put64(at+32, size)
		put32(at+40, link)
		put32(at+44, info)
		put64(at+48, align)
		put64(at+56, entry)
	}
	section(1, 1, 1, 6, 0x1000, 0x1000, 0x288, 4, 0, 0, 0)
	section(2, 7, 2, 0, 0, 0x3200, uint64(24*(len(functions)+1)), 8, 24, 3, 1)
	section(3, 15, 3, 0, 0, 0x3300, uint64(len(names)), 1, 0, 0, 0)
	section(4, 23, 3, 0, 0, 0x3380, uint64(len(shnames)), 1, 0, 0, 0)
	path := filepath.Join(t.TempDir(), "compat.so")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
