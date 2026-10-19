# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Builder & Integration Test Runner (Rust + SoftHSMv2 2.6.1 on Debian)
# ==============================================================================
FROM rust:1-bookworm AS test

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    libsofthsm2-dev \
    opensc \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Ensure /usr/lib/softhsm/libsofthsm2.so is always available across architectures
RUN mkdir -p /usr/lib/softhsm && \
    if [ ! -e /usr/lib/softhsm/libsofthsm2.so ]; then \
        SO_PATH="$(find /usr/lib -name 'libsofthsm2.so' | head -n 1)" && \
        ln -s "${SO_PATH}" /usr/lib/softhsm/libsofthsm2.so; \
    fi

WORKDIR /workspace
COPY . /workspace-src

# Support both `docker build -f signer/Dockerfile .` and `docker build -f signer/Dockerfile signer`
RUN if [ -f /workspace-src/signer/Cargo.toml ]; then \
        cp -R /workspace-src/signer /workspace/signer && \
        if [ -d /workspace-src/vectors ]; then cp -R /workspace-src/vectors /workspace/vectors; fi; \
    else \
        mkdir -p /workspace/signer && \
        cp -R /workspace-src/. /workspace/signer/; \
    fi && \
    rm -rf /workspace-src

WORKDIR /workspace/signer

ENV SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
ENV SIGNER_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

# Build binaries and integration tests
RUN cargo test --no-run && \
    cargo build --release --bins && \
    mkdir -p /out-bin && \
    cp /workspace/signer/target/release/bootstrap /out-bin/bootstrap && \
    if [ -f /workspace/signer/target/release/signer ]; then \
        cp /workspace/signer/target/release/signer /out-bin/signer; \
    fi

# Default command in `test` stage runs the live SoftHSMv2 integration suite
CMD ["cargo", "test", "--test", "hsm_integration", "--", "--nocapture"]

# ==============================================================================
# Stage 2: Minimal Hardened Runtime Image (Debian Bookworm Slim + SoftHSMv2 2.6.1)
# ==============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    softhsm2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/lib/softhsm && \
    if [ ! -e /usr/lib/softhsm/libsofthsm2.so ]; then \
        SO_PATH="$(find /usr/lib -name 'libsofthsm2.so' | head -n 1)" && \
        ln -s "${SO_PATH}" /usr/lib/softhsm/libsofthsm2.so; \
    fi

# Create non-root runtime user and configure SoftHSM config & token directory permissions
RUN groupadd -g 10001 polyglot && \
    useradd -u 10001 -g polyglot -G softhsm -d /var/lib/polyglot -m -s /usr/sbin/nologin polyglot && \
    mkdir -p /var/lib/softhsm/tokens /etc/softhsm && \
    printf "directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" > /etc/softhsm/softhsm2.conf && \
    chmod 0644 /etc/softhsm/softhsm2.conf && \
    chown -R polyglot:polyglot /var/lib/softhsm /var/lib/polyglot /etc/softhsm

COPY --from=test /out-bin/ /usr/local/bin/

ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
ENV SIGNER_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

USER polyglot:polyglot
WORKDIR /var/lib/polyglot

CMD ["/usr/local/bin/signer"]
