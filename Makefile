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

# In-process end-to-end tests on fakes. test/e2e is written in wave 4; until
# then this target is a placeholder that does nothing and succeeds.
e2e:
	@if [ -d test/e2e ]; then $(DEV) go test -race -count=1 ./test/e2e/...; \
	else echo "e2e: not implemented until wave 4"; fi

# PLACEHOLDER: real upstream adapter against Pebble + challtestsrv containers.
# Not implemented until wave 4; prints a notice and exits 0.
e2e-pebble:
	@echo "e2e-pebble: not implemented until wave 4"

# PLACEHOLDER: real certbot / acme.sh containers against a Pebble-backed
# broker. Not implemented until wave 4; prints a notice and exits 0.
compat:
	@echo "compat: not implemented until wave 4"

clean:
	rm -rf bin .cache
