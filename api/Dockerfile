# syntax=docker/dockerfile:1

# Stage 1: Builder
FROM golang:latest AS builder

WORKDIR /src
COPY . /workspace-src

# Support building from root context or api/ directory
RUN if [ -f /workspace-src/api/go.mod ]; then \
        cp -R /workspace-src/api/. /src/ && \
        if [ -d /workspace-src/migrations ]; then mkdir -p /migrations && cp -R /workspace-src/migrations/* /migrations/; else mkdir -p /migrations; fi; \
    else \
        cp -R /workspace-src/. /src/ && \
        mkdir -p /migrations; \
    fi && \
    rm -rf /workspace-src

WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /polyglot-api ./cmd/api

# Stage 2: Minimal Distroless Runtime
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

USER 65532:65532
WORKDIR /app

COPY --from=builder /polyglot-api /usr/local/bin/polyglot-api
COPY --from=builder /migrations /app/migrations

ENV MIGRATIONS_PATH=file:///app/migrations
ENV PUBLIC_ADDR=:8080
ENV INTERNAL_ADDR=:8081

EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/polyglot-api"]
