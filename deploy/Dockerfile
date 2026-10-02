# Build from the repository root:
#   docker build --network host -f deploy/Dockerfile -t tls-broker .
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
      -o /out/tls-broker ./cmd/tls-broker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tls-broker /usr/local/bin/tls-broker
ENV TLS_BROKER_DATA_DIR=/data
VOLUME /data
ENTRYPOINT ["/usr/local/bin/tls-broker"]
