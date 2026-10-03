package direct

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"tls-broker/internal/names"
)

// File names inside a generation and of the active-generation link.
const (
	KeyFile   = "privkey.pem"
	ChainFile = "fullchain.pem"

	generationsDir = "generations"
	currentLink    = "current"
	tmpPrefix      = ".tmp-"
	// wildcardDirPrefix replaces the "*." label in directory names, so no
	// path ever contains "*": "*.example.com" -> "_wildcard.example.com".
	// A normalized name never starts with "_", so the mapping is
	// unambiguous.
	wildcardDirPrefix = "_wildcard."
	maxGeneration     = 999999
)

// File modes of the two files and of the directories the broker creates.
const (
	keyMode   fs.FileMode = 0o600
	chainMode fs.FileMode = 0o644
	dirMode   fs.FileMode = 0o700
)

// DirName returns the directory name of an identifier under <data>/certs:
// the identifier itself, or "_wildcard.<base>" for "*.<base>".
func DirName(identifier string) string {
	if names.IsWildcard(identifier) {
		return wildcardDirPrefix + names.Base(identifier)
	}
	return identifier
}

// Generation is one complete, verified set of key and certificate files.
type Generation struct {
	Number   int
	KeyPEM   []byte // PKCS#1 "RSA PRIVATE KEY", LF line endings
	ChainPEM []byte // leaf first, intermediates, no root, LF line endings
	Key      *rsa.PrivateKey
	Chain    []*x509.Certificate // Chain[0] is the leaf
	// ModTime is when the generation was written (the mtime of its files).
	ModTime time.Time
}

// Leaf returns the leaf certificate.
func (g *Generation) Leaf() *x509.Certificate { return g.Chain[0] }

// Files manages the generation directories of every direct-mode identifier
// below one root (<data>/certs), exactly as architecture §12 describes:
//
//	<root>/<dir>/generations/000001/{privkey.pem,fullchain.pem}
//	<root>/<dir>/current -> generations/000001
//
// Callers serialize writes per identifier (the service does so with its
// per-identifier job); reads may run concurrently with writes.
type Files struct {
	root string
	keep int
}

// NewFiles returns the generation manager for root. keep is how many
// numbered generations Prune leaves per identifier (at least 1; the active
// one is never removed).
func NewFiles(root string, keep int) *Files {
	if keep < 1 {
		keep = 1
	}
	return &Files{root: root, keep: keep}
}

// Root returns the directory holding every identifier directory.
func (f *Files) Root() string { return f.root }

// Identifiers returns every identifier that has a directory under Root,
// sorted. A missing root is an empty list.
func (f *Files) Identifiers() ([]string, error) {
	entries, err := os.ReadDir(f.root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		id := e.Name()
		if rest, ok := strings.CutPrefix(id, wildcardDirPrefix); ok {
			id = names.Wildcard(rest)
		}
		if _, err := names.Normalize(id); err != nil {
			continue // not one of ours
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

func (f *Files) identDir(identifier string) string {
	return filepath.Join(f.root, DirName(identifier))
}

func genName(n int) string { return fmt.Sprintf("%06d", n) }

// Path returns the directory of generation n of the identifier.
func (f *Files) Path(identifier string, n int) string {
	return filepath.Join(f.identDir(identifier), generationsDir, genName(n))
}

// EncodeKey returns the PKCS#1 PEM encoding used for privkey.pem.
func EncodeKey(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// Write stores a new generation of the identifier and makes it current:
//
//  1. the files are written into a temporary directory, each fsynced;
//  2. the material is verified: the key is RSA, the leaf's public key is
//     the key's, the leaf names exactly the identifier among its DNS
//     names, every certificate of the chain parses and each one is signed
//     by the next;
//  3. the temporary directory is fsynced and renamed to the next number,
//     and the generations directory is fsynced;
//  4. the "current" link is switched atomically (new link renamed over the
//     old one) and the identifier directory is fsynced.
//
// Write does not prune; the caller calls Prune afterwards.
//
// The chain is re-encoded with LF line endings and without any self-signed
// (root) certificate after the leaf. at becomes the files' mtime. On error
// nothing visible changes (a leftover temporary directory is removed by the
// next Prune).
func (f *Files) Write(identifier string, key *rsa.PrivateKey, chainPEM []byte, at time.Time) (*Generation, error) {
	chain, err := parseChain(chainPEM)
	if err != nil {
		return nil, err
	}
	chain = dropRoots(chain)
	g := &Generation{KeyPEM: EncodeKey(key), ChainPEM: encodeChain(chain), Key: key, Chain: chain}
	if err := verifyMaterial(identifier, g); err != nil {
		return nil, err
	}

	gensDir := filepath.Join(f.identDir(identifier), generationsDir)
	fresh := false
	if _, err := os.Stat(f.identDir(identifier)); err != nil {
		fresh = true
	}
	if err := os.MkdirAll(gensDir, dirMode); err != nil {
		return nil, err
	}
	if fresh {
		// A new identifier directory must survive a crash as well as the
		// generation inside it, or SQLite would reference a directory that
		// is gone and the next start would issue again.
		if err := syncDir(f.root); err != nil {
			return nil, err
		}
	}
	nums, err := f.List(identifier)
	if err != nil {
		return nil, err
	}
	n := 1
	if len(nums) > 0 {
		n = nums[len(nums)-1] + 1
	}
	if n > maxGeneration {
		return nil, fmt.Errorf("direct: %s: generation numbers exhausted", identifier)
	}

	tmp, err := os.MkdirTemp(gensDir, tmpPrefix+genName(n)+"-")
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	mtime := at.Truncate(time.Second)
	if err := writeFileSync(filepath.Join(tmp, KeyFile), g.KeyPEM, keyMode, mtime); err != nil {
		return nil, err
	}
	if err := writeFileSync(filepath.Join(tmp, ChainFile), g.ChainPEM, chainMode, mtime); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, dirMode); err != nil {
		return nil, err
	}
	if err := syncDir(tmp); err != nil {
		return nil, err
	}
	final := filepath.Join(gensDir, genName(n))
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	ok = true
	if err := syncDir(gensDir); err != nil {
		return nil, err
	}
	if err := f.Activate(identifier, n); err != nil {
		return nil, err
	}
	g.Number = n
	g.ModTime = mtime
	return g, nil
}

// Activate atomically points the identifier's "current" link at generation
// n (which must exist) and fsyncs the directory.
func (f *Files) Activate(identifier string, n int) error {
	dir := f.identDir(identifier)
	if _, err := os.Stat(f.Path(identifier, n)); err != nil {
		return err
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(dir, tmpPrefix+currentLink+"-"+hex.EncodeToString(rnd[:]))
	if err := os.Symlink(filepath.Join(generationsDir, genName(n)), tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, currentLink)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// Current returns the generation number the "current" link points at;
// fs.ErrNotExist when there is no link, an error when it points at
// something that is not a numbered generation.
func (f *Files) Current(identifier string) (int, error) {
	target, err := os.Readlink(filepath.Join(f.identDir(identifier), currentLink))
	if err != nil {
		return 0, err
	}
	dir, base := filepath.Split(filepath.Clean(target))
	n, ok := parseGenName(base)
	if !ok || filepath.Clean(dir) != generationsDir {
		return 0, fmt.Errorf("direct: %s: current link has unexpected target %q", identifier, target)
	}
	return n, nil
}

// List returns the numbers of the identifier's generation directories in
// ascending order, complete or not. No directory is not an error.
func (f *Files) List(identifier string) ([]int, error) {
	ents, err := os.ReadDir(filepath.Join(f.identDir(identifier), generationsDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []int
	for _, e := range ents {
		if n, ok := parseGenName(e.Name()); ok && e.IsDir() {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Load reads and verifies generation n of the identifier. A generation that
// is missing a file or fails verification is an error (fs.ErrNotExist when
// the directory does not exist).
func (f *Files) Load(identifier string, n int) (*Generation, error) {
	dir := f.Path(identifier, n)
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	chainPEM, err := os.ReadFile(filepath.Join(dir, ChainFile))
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("direct: %s generation %d: %w", identifier, n, err)
	}
	chain, err := parseChain(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("direct: %s generation %d: %w", identifier, n, err)
	}
	g := &Generation{Number: n, KeyPEM: keyPEM, ChainPEM: chainPEM, Key: key, Chain: chain, ModTime: st.ModTime().UTC()}
	if err := verifyMaterial(identifier, g); err != nil {
		return nil, fmt.Errorf("direct: %s generation %d: %w", identifier, n, err)
	}
	return g, nil
}

// Newest returns the highest-numbered generation that loads and verifies;
// fs.ErrNotExist when there is none.
func (f *Files) Newest(identifier string) (*Generation, error) {
	nums, err := f.List(identifier)
	if err != nil {
		return nil, err
	}
	for i := len(nums) - 1; i >= 0; i-- {
		if g, err := f.Load(identifier, nums[i]); err == nil {
			return g, nil
		}
	}
	return nil, fs.ErrNotExist
}

// Prune removes leftover temporary directories and links, and every
// numbered generation older than the newest keep ones. The generation the
// "current" link points at is never removed.
func (f *Files) Prune(identifier string) error {
	dir := f.identDir(identifier)
	gensDir := filepath.Join(dir, generationsDir)
	for _, d := range []string{dir, gensDir} {
		ents, err := os.ReadDir(d)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), tmpPrefix) {
				if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
					return err
				}
			}
		}
	}
	nums, err := f.List(identifier)
	if err != nil {
		return err
	}
	cur, curErr := f.Current(identifier)
	removed := false
	for i := 0; i < len(nums)-f.keep; i++ {
		if curErr == nil && nums[i] == cur {
			continue
		}
		if err := os.RemoveAll(filepath.Join(gensDir, genName(nums[i]))); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncDir(gensDir)
	}
	return nil
}

func parseGenName(s string) (int, bool) {
	if len(s) != 6 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

func parseKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	b, rest := pem.Decode(keyPEM)
	if b == nil || b.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("privkey.pem is not a PKCS#1 RSA PRIVATE KEY")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("privkey.pem has trailing data")
	}
	if len(b.Headers) != 0 {
		return nil, errors.New("privkey.pem is encrypted or has headers")
	}
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}

func parseChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := chainPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("chain contains a %q PEM block", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("chain does not parse: %w", err)
		}
		out = append(out, c)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("chain has trailing data")
	}
	if len(out) == 0 {
		return nil, errors.New("chain contains no certificate")
	}
	return out, nil
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// dropRoots removes self-signed certificates after the leaf.
func dropRoots(chain []*x509.Certificate) []*x509.Certificate {
	out := chain[:1:1]
	for _, c := range chain[1:] {
		if !isSelfSigned(c) {
			out = append(out, c)
		}
	}
	return out
}

func encodeChain(chain []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range chain {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

// verifyMaterial checks that the key belongs to the leaf, that the leaf
// covers the identifier, and that each certificate is signed by the next.
func verifyMaterial(identifier string, g *Generation) error {
	if g.Key == nil || len(g.Chain) == 0 {
		return errors.New("incomplete key material")
	}
	leaf := g.Chain[0]
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(g.Key.Public()) {
		return errors.New("private key does not match the leaf certificate")
	}
	if !slices.Contains(leaf.DNSNames, identifier) {
		return fmt.Errorf("leaf certificate does not name %s", identifier)
	}
	for i := 0; i+1 < len(g.Chain); i++ {
		if err := g.Chain[i].CheckSignatureFrom(g.Chain[i+1]); err != nil {
			return fmt.Errorf("chain certificate %d is not signed by the next: %w", i, err)
		}
	}
	return nil
}

func writeFileSync(path string, data []byte, mode fs.FileMode, mtime time.Time) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		return err
	}
	if err := fh.Chmod(mode); err != nil { // umask may have narrowed it
		_ = fh.Close()
		return err
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		_ = fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
