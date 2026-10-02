// Package deps pins the module's external dependencies.
//
// TEMPORARY: go.mod is written once by the skeleton step and later steps must
// not edit it. The list is deliberately wider than the bare modules (extra
// lego, Prometheus and x/crypto packages) so go.sum also covers the transitive
// modules those packages need. Until every dependency is imported by real code, these blank
// imports keep `go mod tidy` from pruning them. The app-wiring step (wave 4)
// deletes this package once all of them are in use.
package deps

import (
	_ "github.com/aws/aws-sdk-go-v2/aws"
	_ "github.com/aws/aws-sdk-go-v2/config"
	_ "github.com/aws/aws-sdk-go-v2/credentials"
	_ "github.com/aws/aws-sdk-go-v2/service/route53"
	_ "github.com/aws/smithy-go"
	_ "github.com/go-acme/lego/v5/acme"
	_ "github.com/go-acme/lego/v5/acme/api"
	_ "github.com/go-acme/lego/v5/certcrypto"
	_ "github.com/go-acme/lego/v5/certificate"
	_ "github.com/go-acme/lego/v5/challenge/dns01"
	_ "github.com/go-acme/lego/v5/lego"
	_ "github.com/go-acme/lego/v5/registration"
	_ "github.com/go-jose/go-jose/v4"
	_ "github.com/go-ldap/ldap/v3"
	_ "github.com/miekg/dns"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/collectors"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/prometheus/client_golang/prometheus/testutil"
	_ "golang.org/x/crypto/acme"
	_ "golang.org/x/crypto/bcrypt"
	_ "golang.org/x/net/idna"
	_ "golang.org/x/net/publicsuffix"
	_ "golang.org/x/sync/errgroup"
	_ "golang.org/x/sync/singleflight"
	_ "gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)
