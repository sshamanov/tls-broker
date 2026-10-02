package dns01

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func TestQuoteUnquoteTXT(t *testing.T) {
	long := strings.Repeat("x", 300)
	cases := []struct{ in, quoted string }{
		{"abc-DEF_123", `"abc-DEF_123"`},
		{`a"b\c`, `"a\"b\\c"`},
		{long, `"` + long[:255] + `" "` + long[255:] + `"`},
	}
	for _, c := range cases {
		q := QuoteTXT(c.in)
		if q != c.quoted {
			t.Errorf("QuoteTXT(%q) = %q, want %q", c.in, q, c.quoted)
		}
		back, err := UnquoteTXT(q)
		if err != nil || back != c.in {
			t.Errorf("UnquoteTXT(%q) = %q, %v", q, back, err)
		}
	}
	for in, want := range map[string]string{
		`"a" "b"`:   "ab",
		`plain`:     "plain",
		`"\065BC"`:  "ABC",
		`"x\"y"`:    `x"y`,
		` "spaced"`: "spaced",
	} {
		if got, err := UnquoteTXT(in); err != nil || got != want {
			t.Errorf("UnquoteTXT(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{`"open`, ``, `"\`, `"\999"`} {
		if _, err := UnquoteTXT(bad); err == nil {
			t.Errorf("UnquoteTXT(%q) succeeded", bad)
		}
	}
}

func TestCheckValue(t *testing.T) {
	if err := checkValue("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "tab\there", "é", strings.Repeat("a", maxValueLen+1)} {
		if err := checkValue(bad); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("checkValue(%q) = %v", bad, err)
		}
	}
}

func TestSecretCredentials(t *testing.T) {
	ctx := context.Background()
	clock := coretest.NewFakeClock()
	secrets := coretest.NewFakeSecrets()
	p := &secretCredentials{secrets: secrets, idName: "aws-id", keyName: "aws-key", clock: clock}
	if _, err := p.Retrieve(ctx); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing secret: err = %v", err)
	}
	_ = secrets.Put(ctx, "aws-id", []byte("AKIDEXAMPLE\n"))
	_ = secrets.Put(ctx, "aws-key", []byte("secret"))
	c, err := p.Retrieve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "AKIDEXAMPLE" || c.SecretAccessKey != "secret" || !c.CanExpire || !c.Expires.Equal(clock.Now().Add(credentialsRefresh)) {
		t.Fatalf("credentials = %+v", c)
	}
}

func TestNewRoute53Client(t *testing.T) {
	// Keep the host's AWS configuration out of the test.
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	ctx := context.Background()
	secrets := coretest.NewFakeSecrets()
	cfg := core.DefaultConfig().Route53
	cfg.AccessKeyIDSecret, cfg.SecretAccessKeySecret = "aws-id", "aws-key"

	if _, err := NewRoute53Client(ctx, cfg, secrets, nil); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing secrets: err = %v", err)
	}
	_ = secrets.Put(ctx, "aws-id", []byte("AKIDEXAMPLE"))
	_ = secrets.Put(ctx, "aws-key", []byte("secret"))
	c, err := NewRoute53Client(ctx, cfg, secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := c.Options().Credentials.Retrieve(ctx)
	if err != nil || creds.AccessKeyID != "AKIDEXAMPLE" {
		t.Fatalf("client credentials = %+v, %v", creds, err)
	}
	if c.Options().Region != "us-east-1" {
		t.Fatalf("region = %q", c.Options().Region)
	}

	// Without secret names the default chain is used (here: environment).
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	c, err = NewRoute53Client(ctx, core.DefaultConfig().Route53, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	creds, err = c.Options().Credentials.Retrieve(ctx)
	if err != nil || creds.AccessKeyID != "AKIDENV" {
		t.Fatalf("default chain credentials = %+v, %v", creds, err)
	}
}
