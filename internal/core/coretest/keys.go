package coretest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
)

// GenKey returns a new ECDSA P-256 key (fast; use it unless RSA matters).
func GenKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// GenRSAKey returns a new RSA-2048 key (slow under the race detector; share
// one per test where possible).
func GenRSAKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

// MakeCSR returns a DER certificate request signed by key with the names as
// DNS SANs (first name also as common name). Names are used as given.
func MakeCSR(key crypto.Signer, dnsNames ...string) []byte {
	if len(dnsNames) == 0 {
		panic("coretest.MakeCSR: no names")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsNames[0]},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		panic(err)
	}
	return der
}

// ParseChain parses a PEM chain into certificates, leaf first.
func ParseChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := chainPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, errors.New("unexpected PEM block " + b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates in PEM")
	}
	return out, nil
}
