# Build from the repository root:
#   make image          (tags tls-broker:local)
#   docker build --network host -f deploy/Dockerfile -t tls-broker:local .
#
# The image holds two static binaries: tls-broker (the service, entrypoint)
# and mockdoh (a development-only DoH mock, see docs/development.md), and
# the user guide (docs/guide) that the web UI's Documentation reader serves.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X tls-broker/internal/version.Version=${VERSION}" \
      -o /out/tls-broker ./cmd/tls-broker && \
    go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/mockdoh ./cmd/mockdoh

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tls-broker /out/mockdoh /usr/local/bin/
COPY docs/guide /usr/share/tls-broker/docs
ENV TLS_BROKER_DATA_DIR=/data
VOLUME /data
# Probes TLS_BROKER_LISTEN (a wildcard host is probed on 127.0.0.1).
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/tls-broker", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/tls-broker"]
