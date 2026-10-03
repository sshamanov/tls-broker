# Everything runs in docker through scripts/dev; Go is not needed on the host.

IMAGE   ?= tls-broker:local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X tls-broker/internal/version.Version=$(VERSION)
DEV     := scripts/dev

.PHONY: check fmt test build image run-test e2e e2e-pebble compat clean

# The gate every commit must pass: formatting, vet, race tests.
check:
	$(DEV) sh -c 'out="$$(gofmt -l cmd internal $$( [ -d test ] && echo test ))"; \
		if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi; \
		go vet ./... && go test -race ./...'

fmt:
	$(DEV) gofmt -w cmd internal $(wildcard test)

test:
	$(DEV) go test ./...

# Static binaries: bin/tls-broker and the development-only bin/mockdoh.
build:
	CGO_ENABLED=0 $(DEV) go build -trimpath -ldflags '$(LDFLAGS)' -o bin/tls-broker ./cmd/tls-broker
	CGO_ENABLED=0 $(DEV) go build -trimpath -ldflags '-s -w' -o bin/mockdoh ./cmd/mockdoh

# Image with both binaries, tagged tls-broker:local by default.
image:
	docker build --network host -f deploy/Dockerfile --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# Start the local test deployment (gitignored deploy/compose.test.yaml, built
# from deploy/compose.prod.example.yaml; it carries live credentials).
run-test:
	docker compose -f deploy/compose.test.yaml up -d

# In-process end-to-end tests on fakes (also part of `make check`).
e2e:
	$(DEV) go test -race -count=1 ./test/e2e/...

# The broker with the real upstream adapter against Pebble + challtestsrv
# containers (test/pebble.sh). Skipped with a message when Pebble's ports are
# taken. The lock serializes runs that share the containers.
PEBBLE_LOCK := .claude/tmp/pebble.lock
e2e-pebble:
	@mkdir -p .claude/tmp
	@flock $(PEBBLE_LOCK) sh -c 'test/pebble.sh start; rc=$$?; \
		if [ $$rc -eq 3 ]; then echo "e2e-pebble: SKIPPED (ports busy)"; exit 0; fi; \
		[ $$rc -eq 0 ] || exit $$rc; \
		$(DEV) env TLS_BROKER_PEBBLE_DIRECTORY=https://127.0.0.1:14000/dir \
			TLS_BROKER_PEBBLE_ROOT=/src/.claude/tmp/e2e/pebble.minica.pem \
			TLS_BROKER_PEBBLE_ISSUER_ROOT=/src/.claude/tmp/e2e/pebble-root.pem \
			TLS_BROKER_PEBBLE_CHALLTESTSRV=http://127.0.0.1:8055 \
			go test -race -tags pebble -count=1 -run TestPebble -v ./test/e2e/; rc=$$?; \
		test/pebble.sh stop; exit $$rc'

# Real certbot (current and old) and acme.sh containers against the broker
# image backed by Pebble, as ACME-proxy and DNS-proxy clients
# (test/compat/run.sh).
compat:
	@mkdir -p .claude/tmp
	@flock $(PEBBLE_LOCK) test/compat/run.sh

clean:
	rm -rf bin .cache
