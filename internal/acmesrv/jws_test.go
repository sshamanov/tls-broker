package acmesrv

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func expectProblem(t *testing.T, r *response, status int, typ string) core.Problem {
	t.Helper()
	if r.StatusCode != status {
		t.Fatalf("status %d, want %d: %s", r.StatusCode, status, r.body)
	}
	p := r.problem(t)
	if p.Type != typ {
		t.Fatalf("problem type %q, want %q: %s", p.Type, typ, r.body)
	}
	if r.Header.Get("Replay-Nonce") == "" {
		t.Fatal("problem response without Replay-Nonce")
	}
	return p
}

func TestJWSErrors(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	newOrder := e.url(pathNewOrder)
	order := map[string]any{"identifiers": []identifierObj{{Type: "dns", Value: "a.example.com"}}}

	t.Run("bad nonce", func(t *testing.T) {
		r := c.post(newOrder, order, func(h map[string]any) { h["nonce"] = "bm90LWEtbm9uY2U" })
		p := expectProblem(t, r, 400, core.ProblemBadNonce)
		if !strings.Contains(p.Detail, "JWS has an invalid anti-replay nonce") {
			t.Fatalf("detail %q", p.Detail)
		}
	})
	t.Run("missing nonce", func(t *testing.T) {
		expectProblem(t, c.post(newOrder, order, func(h map[string]any) { delete(h, "nonce") }), 400, core.ProblemBadNonce)
	})
	t.Run("replayed nonce", func(t *testing.T) {
		h := c.header(newOrder)
		body := signJWS(c.key, h, encodePayload(order))
		if r := c.send(newOrder, body, "application/jose+json"); r.StatusCode != http.StatusCreated {
			t.Fatalf("first use: %d %s", r.StatusCode, r.body)
		}
		expectProblem(t, c.send(newOrder, body, "application/jose+json"), 400, core.ProblemBadNonce)
	})
	t.Run("expired nonce", func(t *testing.T) {
		h := c.header(newOrder)
		e.clock.Advance(DefaultNonceTTL + time.Second)
		expectProblem(t, c.send(newOrder, signJWS(c.key, h, encodePayload(order)), "application/jose+json"), 400, core.ProblemBadNonce)
	})
	t.Run("wrong url", func(t *testing.T) {
		r := c.post(newOrder, order, func(h map[string]any) { h["url"] = e.url(pathNewAccount) })
		expectProblem(t, r, 403, core.ProblemUnauthorized)
	})
	t.Run("missing url", func(t *testing.T) {
		expectProblem(t, c.post(newOrder, order, func(h map[string]any) { delete(h, "url") }), 400, core.ProblemMalformed)
	})
	t.Run("jwk and kid", func(t *testing.T) {
		r := c.post(newOrder, order, func(h map[string]any) { h["jwk"] = jwkJSON(c.key) })
		expectProblem(t, r, 400, core.ProblemMalformed)
	})
	t.Run("jwk on newOrder", func(t *testing.T) {
		r := c.post(newOrder, order, func(h map[string]any) { delete(h, "kid"); h["jwk"] = jwkJSON(c.key) })
		expectProblem(t, r, 400, core.ProblemMalformed)
	})
	t.Run("kid on newAccount", func(t *testing.T) {
		expectProblem(t, c.post(e.url(pathNewAccount), map[string]any{}), 400, core.ProblemMalformed)
	})
	t.Run("unknown account", func(t *testing.T) {
		r := c.post(newOrder, order, func(h map[string]any) { h["kid"] = e.url(pathAccount + "nope") })
		expectProblem(t, r, 400, core.ProblemAccountDoesNotExist)
	})
	t.Run("foreign kid", func(t *testing.T) {
		r := c.post(newOrder, order, func(h map[string]any) { h["kid"] = "https://other.test/acct/1" })
		expectProblem(t, r, 400, core.ProblemAccountDoesNotExist)
	})
	t.Run("wrong key for account", func(t *testing.T) {
		other := &rawClient{e: e, key: coretest.GenKey(), kid: c.kid}
		expectProblem(t, other.post(newOrder, order), 400, core.ProblemMalformed)
	})
	t.Run("unsupported algorithm", func(t *testing.T) {
		for _, alg := range []string{"HS256", "none", "EdDSA", "PS256"} {
			r := c.post(newOrder, order, func(h map[string]any) { h["alg"] = alg })
			expectProblem(t, r, 400, core.ProblemBadSignatureAlgorithm)
		}
	})
	t.Run("algorithm does not fit key", func(t *testing.T) {
		r := c.post(newOrder, order, func(h map[string]any) { h["alg"] = "ES384" })
		expectProblem(t, r, 400, core.ProblemBadSignatureAlgorithm)
	})
	t.Run("content type", func(t *testing.T) {
		body := signJWS(c.key, c.header(newOrder), encodePayload(order))
		r := c.send(newOrder, body, "application/json")
		expectProblem(t, r, 415, core.ProblemMalformed)
		// Parameters are tolerated.
		body = signJWS(c.key, c.header(newOrder), encodePayload(order))
		if r := c.send(newOrder, body, "application/jose+json; charset=utf-8"); r.StatusCode != http.StatusCreated {
			t.Fatalf("with parameters: %d %s", r.StatusCode, r.body)
		}
	})
	t.Run("not a JWS", func(t *testing.T) {
		expectProblem(t, c.send(newOrder, []byte(`{"hello":1}`), "application/jose+json"), 400, core.ProblemMalformed)
		expectProblem(t, c.send(newOrder, []byte(`x.y.z`), "application/jose+json"), 400, core.ProblemMalformed)
	})
	t.Run("general serialization", func(t *testing.T) {
		var flat map[string]string
		_ = json.Unmarshal(signJWS(c.key, c.header(newOrder), encodePayload(order)), &flat)
		body, _ := json.Marshal(map[string]any{"payload": flat["payload"],
			"signatures": []map[string]string{{"protected": flat["protected"], "signature": flat["signature"]}}})
		expectProblem(t, c.send(newOrder, body, "application/jose+json"), 400, core.ProblemMalformed)
	})
	t.Run("body too large", func(t *testing.T) {
		big := bytes.Repeat([]byte("a"), DefaultMaxBodyBytes+1)
		expectProblem(t, c.send(newOrder, big, "application/jose+json"), 413, core.ProblemMalformed)
	})
	t.Run("small RSA key", func(t *testing.T) {
		expectProblem(t, e.newRaw(smallRSAKey(t)).post(e.url(pathNewAccount), map[string]any{}), 400, core.ProblemBadPublicKey)
	})
	t.Run("old client resource field", func(t *testing.T) {
		r := c.post(newOrder, map[string]any{"resource": "new-order",
			"identifiers": []identifierObj{{Type: "dns", Value: "b.example.com"}}})
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("%d %s", r.StatusCode, r.body)
		}
	})
}

func TestNewAccount(t *testing.T) {
	e := newEnv(t)
	key := coretest.GenKey()
	c := e.newRaw(key)

	r := c.post(e.url(pathNewAccount), map[string]any{"onlyReturnExisting": true})
	expectProblem(t, r, 400, core.ProblemAccountDoesNotExist)

	r = c.post(e.url(pathNewAccount), map[string]any{"contact": []string{"tel:+1"}})
	expectProblem(t, r, 400, core.ProblemUnsupportedContact)

	// termsOfServiceAgreed is accepted whatever it says.
	r = c.post(e.url(pathNewAccount), map[string]any{"termsOfServiceAgreed": false, "contact": []string{"mailto:a@example.com"}})
	if r.StatusCode != http.StatusCreated || r.Header.Get("Location") == "" || !strings.Contains(string(r.body), `"status":"valid"`) {
		t.Fatalf("create: %d %s", r.StatusCode, r.body)
	}
	loc := r.Header.Get("Location")
	r = c.post(e.url(pathNewAccount), map[string]any{"onlyReturnExisting": true})
	if r.StatusCode != http.StatusOK || r.Header.Get("Location") != loc {
		t.Fatalf("existing: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	// RSA keys work too.
	rc := e.newRaw(coretest.GenRSAKey()).register()
	if !strings.HasPrefix(rc.kid, e.url(pathAccount)) {
		t.Fatalf("rsa kid %q", rc.kid)
	}

	// POST "{}" to the account (pre-POST-as-GET Certbot) fetches it.
	c.kid = loc
	r = c.post(loc, map[string]any{})
	if r.StatusCode != http.StatusOK || !strings.Contains(string(r.body), "a@example.com") {
		t.Fatalf("fetch with {}: %d %s", r.StatusCode, r.body)
	}
	// Another account's URL.
	expectProblem(t, rc.post(loc, nil), 403, core.ProblemUnauthorized)
	// Orders list is empty.
	r = c.post(loc+"/orders", nil)
	if r.StatusCode != http.StatusOK || strings.TrimSpace(string(r.body)) != `{"orders":[]}` {
		t.Fatalf("orders: %d %s", r.StatusCode, r.body)
	}
	// Deactivate, then everything is unauthorized, newAccount included.
	if r = c.post(loc, map[string]any{"status": "deactivated"}); r.StatusCode != http.StatusOK {
		t.Fatalf("deactivate: %d %s", r.StatusCode, r.body)
	}
	expectProblem(t, c.post(loc, nil), 403, core.ProblemUnauthorized)
	c.kid = ""
	expectProblem(t, c.post(e.url(pathNewAccount), map[string]any{}), 403, core.ProblemUnauthorized)
}

func TestKeyChangeConflict(t *testing.T) {
	e := newEnv(t)
	a := e.newRaw(coretest.GenKey()).register()
	b := e.newRaw(coretest.GenKey()).register()
	kc := e.url(pathKeyChange)

	inner := func(newKey *rawClient, account string, oldKey json.RawMessage) json.RawMessage {
		return signJWS(newKey.key, map[string]any{"alg": algFor(newKey.key), "jwk": jwkJSON(newKey.key), "url": kc},
			encodePayload(map[string]any{"account": account, "oldKey": oldKey}))
	}
	// New key already bound to b: 409 with b's Location.
	r := a.post(kc, inner(b, a.kid, jwkJSON(a.key)))
	expectProblem(t, r, 409, core.ProblemMalformed)
	if r.Header.Get("Location") != b.kid {
		t.Fatalf("conflict Location %q, want %q", r.Header.Get("Location"), b.kid)
	}
	fresh := e.newRaw(coretest.GenKey())
	// Wrong oldKey.
	expectProblem(t, a.post(kc, inner(fresh, a.kid, jwkJSON(b.key))), 403, core.ProblemUnauthorized)
	// Wrong account.
	expectProblem(t, a.post(kc, inner(fresh, b.kid, jwkJSON(a.key))), 403, core.ProblemUnauthorized)
	// Inner signed by a different key than its jwk.
	bad := signJWS(a.key, map[string]any{"alg": "ES256", "jwk": jwkJSON(fresh.key), "url": kc},
		encodePayload(map[string]any{"account": a.kid, "oldKey": jwkJSON(a.key)}))
	expectProblem(t, a.post(kc, json.RawMessage(bad)), 400, core.ProblemMalformed)
	// Success with a P-384 key.
	p384 := &rawClient{e: e, key: p384Key()}
	innerP384 := signJWS(p384.key, map[string]any{"alg": "ES384", "jwk": jwkJSON(p384.key), "url": kc},
		encodePayload(map[string]any{"account": a.kid, "oldKey": jwkJSON(a.key)}))
	if r := a.post(kc, json.RawMessage(innerP384)); r.StatusCode != http.StatusOK {
		t.Fatalf("keyChange: %d %s", r.StatusCode, r.body)
	}
	p384.kid = a.kid
	if r := p384.post(a.kid, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("new key: %d %s", r.StatusCode, r.body)
	}
}

func TestNonceSingleUseConcurrent(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	h := c.header(c.kid) // one nonce for every request
	const n = 16
	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = signJWS(c.key, h, nil) // distinct signatures (ECDSA is randomized)
	}
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i] = c.send(c.kid, bodies[i], "application/jose+json").StatusCode
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			ok++
		case http.StatusBadRequest:
		default:
			t.Fatalf("status %d", s)
		}
	}
	if ok != 1 {
		t.Fatalf("%d requests accepted the same nonce, want 1 (%v)", ok, statuses)
	}
}

func TestNoncePoolExpiryAndEviction(t *testing.T) {
	clock := coretest.NewFakeClock()
	p := newNoncePool(clock, time.Minute, 3)
	a := p.New()
	clock.Advance(30 * time.Second)
	b := p.New()
	if !p.Use(a) || p.Use(a) {
		t.Fatal("a must be usable exactly once")
	}
	clock.Advance(31 * time.Second)
	if p.Use(b) != true {
		t.Fatal("b is 31s old and must be valid")
	}
	c := p.New()
	clock.Advance(time.Minute)
	if p.Use(c) {
		t.Fatal("expired nonce accepted")
	}
	var ns []string
	for i := 0; i < 5; i++ {
		ns = append(ns, p.New())
	}
	if p.Len() > 3 || p.Use(ns[0]) || !p.Use(ns[4]) {
		t.Fatalf("eviction: len %d", p.Len())
	}
	// Heavy consumption keeps the queue bounded.
	for i := 0; i < 5000; i++ {
		p.Use(p.New())
	}
	p.mu.Lock()
	q := len(p.queue)
	p.mu.Unlock()
	if q > 2*3+1024+1 {
		t.Fatalf("queue grew to %d", q)
	}
}
