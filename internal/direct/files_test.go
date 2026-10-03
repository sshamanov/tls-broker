package direct

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirName(t *testing.T) {
	for in, want := range map[string]string{
		"foo.example.com": "foo.example.com",
		"*.example.com":   "_wildcard.example.com",
		"*.a.example.org": "_wildcard.a.example.org",
	} {
		if got := DirName(in); got != want || strings.Contains(got, "*") {
			t.Errorf("DirName(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeGen(t *testing.T, f *Files, ca *testCA, id string, withRoot bool, at time.Time) *Generation {
	t.Helper()
	k, _ := poolKey(2048)
	_, chain := ca.sign(&k.PublicKey, []string{id}, at, at.Add(90*day), withRoot)
	g, err := f.Write(id, k, chain, at)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestWriteGeneration(t *testing.T) {
	root := t.TempDir()
	f := NewFiles(root, 3)
	ca := newTestCA()
	at := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	g := writeGen(t, f, ca, "*.example.com", true, at)
	if g.Number != 1 {
		t.Fatalf("generation %d, want 1", g.Number)
	}
	dir := filepath.Join(root, "_wildcard.example.com")
	target, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil || target != "generations/000001" {
		t.Fatalf("current -> %q (%v)", target, err)
	}
	gen := filepath.Join(dir, "generations", "000001")
	for name, mode := range map[string]os.FileMode{KeyFile: 0o600, ChainFile: 0o644} {
		st, err := os.Stat(filepath.Join(gen, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode %v, want %v", name, st.Mode().Perm(), mode)
		}
		if !st.ModTime().Equal(at) {
			t.Errorf("%s mtime %v, want %v", name, st.ModTime(), at)
		}
	}
	keyPEM, _ := os.ReadFile(filepath.Join(gen, KeyFile))
	chainPEM, _ := os.ReadFile(filepath.Join(gen, ChainFile))
	if !bytes.HasPrefix(keyPEM, []byte("-----BEGIN RSA PRIVATE KEY-----\n")) || bytes.Contains(keyPEM, []byte("\r")) {
		t.Errorf("key is not LF PKCS#1 PEM:\n%s", keyPEM[:40])
	}
	if bytes.Contains(keyPEM, []byte("ENCRYPTED")) || bytes.Contains(keyPEM, []byte("Proc-Type")) {
		t.Error("key is encrypted")
	}
	if bytes.Contains(chainPEM, []byte("\r")) {
		t.Error("chain has CR")
	}
	chain, err := parseChain(chainPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[1].Subject.CommonName != "Test Intermediate" {
		t.Fatalf("chain must be leaf + intermediate without root, got %d certificates", len(chain))
	}

	g2 := writeGen(t, f, ca, "*.example.com", false, at.Add(time.Hour))
	if g2.Number != 2 {
		t.Fatalf("second generation %d", g2.Number)
	}
	if n, err := f.Current("*.example.com"); err != nil || n != 2 {
		t.Fatalf("Current = %d, %v", n, err)
	}
	loaded, err := f.Load("*.example.com", 1)
	if err != nil || !bytes.Equal(loaded.KeyPEM, keyPEM) || !loaded.ModTime.Equal(at) {
		t.Fatalf("Load(1): %v", err)
	}
}

func TestWriteRejectsInconsistentMaterial(t *testing.T) {
	f := NewFiles(t.TempDir(), 3)
	ca := newTestCA()
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	k1, _ := poolKey(2048)
	k2, _ := poolKey(2048)
	_, chain := ca.sign(&k1.PublicKey, []string{"a.example.com"}, at, at.Add(day), false)

	cases := map[string]func() error{
		"key mismatch": func() error { _, err := f.Write("a.example.com", k2, chain, at); return err },
		"wrong name":   func() error { _, err := f.Write("b.example.com", k1, chain, at); return err },
		"garbage":      func() error { _, err := f.Write("a.example.com", k1, []byte("nope"), at); return err },
		"broken chain": func() error {
			other := newTestCA()
			_, c2 := ca.sign(&k1.PublicKey, []string{"a.example.com"}, at, at.Add(day), false)
			leaf, _ := pem.Decode(c2)
			bad := append(pem.EncodeToMemory(leaf), pemCert(other.inter)...)
			_, err := f.Write("a.example.com", k1, bad, at)
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Errorf("%s: Write succeeded", name)
		}
	}
	for _, id := range []string{"a.example.com", "b.example.com"} {
		if nums, _ := f.List(id); len(nums) != 0 {
			t.Errorf("%s: generations left behind: %v", id, nums)
		}
		if _, err := f.Current(id); err == nil {
			t.Errorf("%s: current link created", id)
		}
	}
}

func TestPrune(t *testing.T) {
	root := t.TempDir()
	f := NewFiles(root, 2)
	ca := newTestCA()
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for i := range 4 {
		writeGen(t, f, ca, "a.example.com", false, at.Add(time.Duration(i)*time.Hour))
	}
	// A leftover from a crash mid-write.
	if err := os.MkdirAll(filepath.Join(root, "a.example.com", "generations", ".tmp-000009-x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.Prune("a.example.com"); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Join(root, "a.example.com", "generations"))
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != "000003,000004" {
		t.Fatalf("after prune: %v", got)
	}
	// The current generation survives even when it is old.
	if err := f.Activate("a.example.com", 3); err != nil {
		t.Fatal(err)
	}
	writeGen(t, f, ca, "a.example.com", false, at.Add(5*time.Hour)) // 5, now current
	if err := f.Activate("a.example.com", 3); err != nil {
		t.Fatal(err)
	}
	writeGen(t, f, ca, "a.example.com", false, at.Add(6*time.Hour)) // 6
	_ = f.Activate("a.example.com", 3)
	if err := f.Prune("a.example.com"); err != nil {
		t.Fatal(err)
	}
	if nums, _ := f.List("a.example.com"); len(nums) != 3 || nums[0] != 3 {
		t.Fatalf("current generation pruned: %v", nums)
	}
}
