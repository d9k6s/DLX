# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY main.go ./
COPY service ./service
COPY translate ./translate
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/deeplx .

FROM alpine:latest
WORKDIR /app
RUN addgroup -S deeplx && \
    adduser -h /app -G deeplx -SH deeplx && \
    mkdir -p /data && \
    chown deeplx:deeplx /data
USER deeplx:deeplx
COPY --from=builder --chown=deeplx:deeplx /out/deeplx /app/deeplx
VOLUME ["/data"]
EXPOSE 1188
ENTRYPOINT ["/app/deeplx"]
