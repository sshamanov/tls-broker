package acmesrv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"tls-broker/internal/core"
	"tls-broker/internal/httpx"
)

// allowedAlgs is the JWS algorithm whitelist (RFC 8555 §6.2 requires RS256
// and recommends ES256; ES384/ES512 cover every EC key Certbot or acme.sh can
// generate).
var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512}

const allowedAlgList = "RS256, ES256, ES384, ES512"

// minRSABits is the smallest RSA account key accepted.
const minRSABits = 2048

// keyMode says which key reference an endpoint requires (RFC 8555 §6.2).
type keyMode int

const (
	useKID keyMode = iota // every request except newAccount and revokeCert
	useJWK                // newAccount (and the inner keyChange JWS)
)

// protectedHeader is the part of the JWS protected header the server reads.
type protectedHeader struct {
	Alg   string          `json:"alg"`
	JWK   json.RawMessage `json:"jwk"`
	KID   string          `json:"kid"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
}

// rawJWS is the flattened JSON serialization (RFC 7515 §7.2.2).
type rawJWS struct {
	Protected  string          `json:"protected"`
	Payload    *string         `json:"payload"`
	Signature  string          `json:"signature"`
	Header     json.RawMessage `json:"header"`
	Signatures json.RawMessage `json:"signatures"`
}

// parsedJWS is a structurally valid JWS whose signature is not yet checked.
type parsedJWS struct {
	body []byte
	hdr  protectedHeader
	jwk  *jose.JSONWebKey // set when the header carries "jwk"
}

// authed is a verified request.
type authed struct {
	payload []byte
	// account is the requesting account (useKID).
	account *core.ACMEAccount
	// jwk and thumbprint describe the signing key (useJWK).
	jwk        *jose.JSONWebKey
	thumbprint string
}

// postAsGet reports whether the payload is the empty POST-as-GET payload.
func (a *authed) postAsGet() bool { return len(a.payload) == 0 }

func malformed(format string, args ...any) *core.Problem {
	return core.NewProblem(core.ProblemMalformed, format, args...)
}

// parseJWS checks the structure of a flattened JWS, decodes its protected
// header, applies the algorithm whitelist and parses an embedded key.
func parseJWS(body []byte) (*parsedJWS, *core.Problem) {
	var raw rawJWS
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, malformed("request body is not a JWS in flattened JSON serialization")
	}
	if len(raw.Signatures) > 0 && string(raw.Signatures) != "null" {
		return nil, malformed("JWS must use the flattened JSON serialization with exactly one signature")
	}
	if len(raw.Header) > 0 && string(raw.Header) != "null" {
		return nil, malformed("JWS must not have an unprotected header")
	}
	if raw.Payload == nil {
		return nil, malformed("JWS has no payload field")
	}
	if raw.Protected == "" || raw.Signature == "" {
		return nil, malformed("JWS has no protected header or no signature")
	}
	hb, err := base64.RawURLEncoding.DecodeString(raw.Protected)
	if err != nil {
		return nil, malformed("JWS protected header is not base64url")
	}
	p := &parsedJWS{body: body}
	if err := json.Unmarshal(hb, &p.hdr); err != nil {
		return nil, malformed("JWS protected header is not a JSON object")
	}
	if !algAllowed(p.hdr.Alg) {
		return nil, core.NewProblem(core.ProblemBadSignatureAlgorithm,
			"JWS signature algorithm %q is not supported; use one of %s", p.hdr.Alg, allowedAlgList)
	}
	hasJWK := len(p.hdr.JWK) > 0 && string(p.hdr.JWK) != "null"
	if hasJWK == (p.hdr.KID != "") {
		return nil, malformed("JWS protected header must contain exactly one of jwk and kid")
	}
	if hasJWK {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(p.hdr.JWK); err != nil || !k.Valid() || !k.IsPublic() {
			return nil, core.NewProblem(core.ProblemBadPublicKey, "JWS jwk is not a valid public key")
		}
		if prob := checkKey(&k, p.hdr.Alg); prob != nil {
			return nil, prob
		}
		p.jwk = &k
	}
	return p, nil
}

func algAllowed(alg string) bool {
	for _, a := range allowedAlgs {
		if string(a) == alg {
			return true
		}
	}
	return false
}

// checkKey enforces the key policy (RSA >= 2048 bits, EC on P-256/384/521)
// and that the algorithm fits the key.
func checkKey(k *jose.JSONWebKey, alg string) *core.Problem {
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSABits {
			return core.NewProblem(core.ProblemBadPublicKey, "RSA account keys must have at least %d bits", minRSABits)
		}
		if alg != string(jose.RS256) {
			return core.NewProblem(core.ProblemBadSignatureAlgorithm, "algorithm %s does not match an RSA key; use RS256", alg)
		}
	case *ecdsa.PublicKey:
		want := map[elliptic.Curve]jose.SignatureAlgorithm{
			elliptic.P256(): jose.ES256, elliptic.P384(): jose.ES384, elliptic.P521(): jose.ES512,
		}[pub.Curve]
		if want == "" {
			return core.NewProblem(core.ProblemBadPublicKey, "unsupported elliptic curve; use P-256, P-384 or P-521")
		}
		if alg != string(want) {
			return core.NewProblem(core.ProblemBadSignatureAlgorithm, "algorithm %s does not match the key's curve; use %s", alg, want)
		}
	default:
		return core.NewProblem(core.ProblemBadPublicKey, "account keys must be RSA or ECDSA")
	}
	return nil
}

// verify checks the signature with key and returns the payload.
func (p *parsedJWS) verify(key *jose.JSONWebKey) ([]byte, *core.Problem) {
	sig, err := jose.ParseSignedJSON(string(p.body), allowedAlgs)
	if err != nil {
		return nil, malformed("JWS could not be parsed")
	}
	payload, err := sig.Verify(key)
	if err != nil {
		return nil, malformed("JWS signature is invalid")
	}
	return payload, nil
}

// thumbprint returns the RFC 7638 SHA-256 thumbprint, base64url.
func thumbprint(k *jose.JSONWebKey) (string, error) {
	b, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// publicJWK returns the JSON of the public part of k, as stored with an
// account.
func publicJWK(k *jose.JSONWebKey) ([]byte, error) {
	pub := k.Public()
	return pub.MarshalJSON()
}

// readJWS reads and parses the body of a JWS POST.
func (s *Server) readJWS(x *exchange) (*parsedJWS, *core.Problem) {
	mt, _, err := mime.ParseMediaType(x.r.Header.Get("Content-Type"))
	// Certbot 0.31's acme library (Debian 10's package) sends the
	// certificate download's POST-as-GET with the Accept type as its
	// Content-Type. The body is still a verified JWS; nothing else is
	// relaxed.
	certbot031 := mt == "application/pem-certificate-chain" && strings.HasPrefix(x.path, pathCert)
	if err != nil || mt != "application/jose+json" && !certbot031 {
		return nil, malformed("Content-Type must be application/jose+json").WithStatus(http.StatusUnsupportedMediaType)
	}
	body, err := io.ReadAll(x.r.Body)
	if err != nil {
		if httpx.IsBodyTooLarge(err) {
			return nil, malformed("request body too large").WithStatus(http.StatusRequestEntityTooLarge)
		}
		return nil, malformed("request body could not be read")
	}
	return parseJWS(body)
}

// authenticate verifies a JWS POST to the current URL (RFC 8555 §6.2–6.5):
// structure, algorithm, key reference, url, signature, then the nonce. On
// failure it writes the problem and returns nil.
func (s *Server) authenticate(x *exchange, mode keyMode) *authed {
	a, prob := s.authenticateJWS(x, mode)
	if prob != nil {
		s.problem(x, prob)
		return nil
	}
	return a
}

func (s *Server) authenticateJWS(x *exchange, mode keyMode) (*authed, *core.Problem) {
	p, prob := s.readJWS(x)
	if prob != nil {
		return nil, prob
	}
	switch {
	case mode == useJWK && p.jwk == nil:
		return nil, malformed("this request must be signed with a jwk header (the account key itself), not kid")
	case mode == useKID && p.jwk != nil:
		return nil, malformed("this request must use a kid header (the account URL), not jwk")
	}
	if p.hdr.URL == "" {
		return nil, malformed("JWS protected header has no url")
	}
	if want := x.url(x.path); p.hdr.URL != want {
		return nil, core.NewProblem(core.ProblemUnauthorized, "JWS url %q does not match the request URL %q", p.hdr.URL, want)
	}
	if p.hdr.Nonce == "" {
		return nil, core.NewProblem(core.ProblemBadNonce, "JWS has no anti-replay nonce")
	}

	a := &authed{}
	key := p.jwk
	if mode == useKID {
		acct, prob := s.accountForKID(x, p.hdr.KID)
		if prob != nil {
			return nil, prob
		}
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(acct.JWK); err != nil {
			s.log.ErrorContext(x.ctx, "stored account key unreadable", "account", acct.ID, "err", err)
			return nil, core.NewProblem(core.ProblemServerInternal, "internal error")
		}
		if prob := checkKey(&k, p.hdr.Alg); prob != nil {
			return nil, prob
		}
		a.account, key = acct, &k
	}
	payload, prob := p.verify(key)
	if prob != nil {
		return nil, prob
	}
	// The nonce is consumed only for a correctly signed request, so a forged
	// request cannot burn a client's nonce. The wording matches Boulder's,
	// which acme.sh recognizes to retry.
	if !s.nonces.Use(p.hdr.Nonce) {
		return nil, core.NewProblem(core.ProblemBadNonce, "JWS has an invalid anti-replay nonce: %q", p.hdr.Nonce)
	}
	a.payload = payload
	if mode == useJWK {
		tp, err := thumbprint(p.jwk)
		if err != nil {
			return nil, core.NewProblem(core.ProblemBadPublicKey, "JWS jwk thumbprint could not be computed")
		}
		a.jwk, a.thumbprint = p.jwk, tp
	} else if a.account.Status != core.AccountValid {
		return nil, core.NewProblem(core.ProblemUnauthorized, "account is %s", a.account.Status)
	}
	return a, nil
}

// accountForKID resolves a kid (an account URL of this server).
func (s *Server) accountForKID(x *exchange, kid string) (*core.ACMEAccount, *core.Problem) {
	id, ok := strings.CutPrefix(kid, x.url(pathAccount))
	if !ok || id == "" || strings.Contains(id, "/") {
		return nil, core.NewProblem(core.ProblemAccountDoesNotExist, "kid %q is not an account URL of this server", kid)
	}
	acct, err := s.o.Accounts.Get(x.ctx, id)
	if errors.Is(err, core.ErrNotFound) {
		return nil, core.NewProblem(core.ProblemAccountDoesNotExist, "account %q does not exist", kid)
	}
	if err != nil {
		s.log.ErrorContext(x.ctx, "account lookup failed", "err", err)
		return nil, core.NewProblem(core.ProblemServerInternal, "internal error")
	}
	return acct, nil
}
