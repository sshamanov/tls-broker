package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"tls-broker/internal/core"
)

// FileSecrets is a core.SecretStore keeping one file per secret under
// <data>/secrets: directory mode 0700, files mode 0600, replaced atomically.
// Values are never logged and never appear in errors.
type FileSecrets struct {
	dir string
	mu  sync.Mutex // serializes writers; readers rely on atomic rename
}

var _ core.SecretStore = (*FileSecrets)(nil)

// NewFileSecrets opens (creating if needed) the secret store of dataDir.
func NewFileSecrets(dataDir string) (*FileSecrets, error) {
	dir := filepath.Join(dataDir, "secrets")
	if err := ensureDir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secrets directory: %w", err)
	}
	return &FileSecrets{dir: dir}, nil
}

func (s *FileSecrets) path(name string) (string, error) {
	if !ValidSecretName(name) {
		return "", fmt.Errorf("invalid secret name %q", name)
	}
	return filepath.Join(s.dir, name), nil
}

// Get implements core.SecretStore.
func (s *FileSecrets) Get(_ context.Context, name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("secret %q: %w", name, core.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("secret %q: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("secret %q is not a regular file", name)
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("secret %q: %w", name, core.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("secret %q: %w", name, err)
	}
	return b, nil
}

// Put implements core.SecretStore.
func (s *FileSecrets) Put(_ context.Context, name string, value []byte) error {
	if _, err := s.path(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFileAtomic(s.dir, name, value, 0o600); err != nil {
		return fmt.Errorf("write secret %q: %w", name, err)
	}
	return nil
}

// Delete implements core.SecretStore.
func (s *FileSecrets) Delete(_ context.Context, name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete secret %q: %w", name, err)
	}
	return syncDir(s.dir)
}

// List implements core.SecretStore.
func (s *FileSecrets) List(_ context.Context) ([]string, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	out := []string{}
	for _, e := range ents {
		if e.Type().IsRegular() && ValidSecretName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}
