package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"tls-broker/internal/core"
)

func TestFileSecretsLifecycle(t *testing.T) {
	ctx := context.Background()
	data := t.TempDir()
	s, err := NewFileSecrets(data)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(data, "secrets")); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	if l, err := s.List(ctx); err != nil || l == nil || len(l) != 0 {
		t.Fatalf("empty list %v %v", l, err)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	for _, n := range []string{"b-key", "a.key"} {
		if err := s.Put(ctx, n, []byte("value-"+n)); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(filepath.Join(data, "secrets", "a.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", fi, err)
	}
	if v, err := s.Get(ctx, "a.key"); err != nil || string(v) != "value-a.key" {
		t.Fatalf("%q %v", v, err)
	}
	if err := s.Put(ctx, "a.key", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(ctx, "a.key"); string(v) != "new" {
		t.Fatalf("not replaced: %q", v)
	}
	if l, _ := s.List(ctx); !slices.Equal(l, []string{"a.key", "b-key"}) {
		t.Fatalf("list %v", l)
	}
	if err := s.Delete(ctx, "a.key"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "a.key"); err != nil {
		t.Fatalf("deleting a missing secret: %v", err)
	}
	if l, _ := s.List(ctx); !slices.Equal(l, []string{"b-key"}) {
		t.Fatalf("list %v", l)
	}
	// No temporary file is left behind and nothing but names is listed.
	ents, _ := os.ReadDir(filepath.Join(data, "secrets"))
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
}

func TestFileSecretsTightensExistingDirectory(t *testing.T) {
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSecrets(data); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(data, "secrets")); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestFileSecretsRejectTraversal(t *testing.T) {
	ctx := context.Background()
	data := t.TempDir()
	s, _ := NewFileSecrets(data)
	outside := filepath.Join(data, "outside")
	os.WriteFile(outside, []byte("x"), 0o600)
	for _, n := range []string{"../outside", "..", ".", "a/b", "/etc/passwd", "", ".hidden", "A", "a\x00b", strings.Repeat("a", 200)} {
		if err := s.Put(ctx, n, []byte("v")); err == nil {
			t.Errorf("Put %q accepted", n)
		}
		if _, err := s.Get(ctx, n); err == nil || errors.Is(err, core.ErrNotFound) {
			t.Errorf("Get %q: %v", n, err)
		}
		if err := s.Delete(ctx, n); err == nil {
			t.Errorf("Delete %q accepted", n)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("file outside the store was touched")
	}
}

func TestFileSecretsRefuseSymlink(t *testing.T) {
	ctx := context.Background()
	data := t.TempDir()
	s, _ := NewFileSecrets(data)
	target := filepath.Join(data, "target")
	os.WriteFile(target, []byte("x"), 0o600)
	os.Symlink(target, filepath.Join(data, "secrets", "link"))
	if _, err := s.Get(ctx, "link"); err == nil {
		t.Fatal("symlink followed")
	}
	if l, _ := s.List(ctx); len(l) != 0 {
		t.Fatalf("symlink listed: %v", l)
	}
}

func TestFileSecretsConcurrentPut(t *testing.T) {
	ctx := context.Background()
	s, _ := NewFileSecrets(t.TempDir())
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Put(ctx, "k", []byte(strings.Repeat(string(rune('a'+i)), 1000)))
			if v, err := s.Get(ctx, "k"); err == nil && strings.Count(string(v), string(v[:1])) != 1000 {
				t.Errorf("torn read")
			}
		}()
	}
	wg.Wait()
}
