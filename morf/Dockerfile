# Stage 1: Build the Go binary (Alpine for smaller size)
FROM golang:1.24-alpine AS go-builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary with optimizations and stripping
# TARGETOS/TARGETARCH are auto-populated by `docker buildx build --platform`.
# Defaults (linux/amd64) apply for plain `docker build` without buildx.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -ldflags="-w -s" -trimpath -o morf .

# Stage 2: Download tools (cached layer)
FROM debian:bullseye-slim AS tools-downloader
ARG JDK_VERSION=11
ARG APKTOOL_VERSION=2.9.3
ARG APKANALYZER_VERSION=1.0.0

# Install curl, wget, and sha256sum for downloading and verifying tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget ca-certificates coreutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create tools directory
RUN mkdir -p /app/tools

# Download apktool with MANDATORY SHA256 verification.
# APKTOOL_SHA256 defaults to the verified checksum of the pinned APKTOOL_VERSION
# (2.9.3, 23254968 bytes — computed from the official GitHub release asset).
# Verification is ALWAYS enforced: a mismatch, or an empty checksum, is fatal.
# This closes the poisoned-jar supply-chain gap (a tampered download can no
# longer be silently accepted). When bumping APKTOOL_VERSION, update this SHA.
ARG APKTOOL_SHA256="7956eb04194300ce0d0a84ad18771eebc94b89fb8d1ddcce8ea4c056818646f4"
RUN if [ -z "${APKTOOL_SHA256}" ]; then \
        echo "FATAL: APKTOOL_SHA256 is empty — refusing to build without an integrity check." >&2; \
        exit 1; \
    fi && \
    curl -fL -o /app/tools/apktool.jar \
        "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" && \
    echo "${APKTOOL_SHA256}  /app/tools/apktool.jar" | sha256sum -c -

# Note: apkanalyzer.jar is included in the repo (already present)
# Copy it from the build context if needed, otherwise it will be copied from repo
RUN echo "Tools downloaded successfully"

# Stage 3: Runtime image (Debian slim)
FROM debian:bullseye-slim
ARG JDK_VERSION=11

# Install runtime dependencies and tools in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates-java \
        openjdk-${JDK_VERSION}-jre-headless \
        openjdk-${JDK_VERSION}-jdk \
        aapt \
        ripgrep && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/oracle-jdk${JDK_VERSION}-installer

# Create required directories
RUN mkdir -p /app/tools && \
    mkdir -p /tmp/morf/input && \
    mkdir -p /tmp/morf/output && \
    chmod -R 700 /tmp/morf

# Copy binary from builder (stripped and optimized)
COPY --from=go-builder /app/morf /usr/local/bin/morf

# Copy tools: apkanalyzer.jar ships in the build context (./morf/tools),
# apktool.jar is downloaded by the tools-downloader stage.
COPY tools/apkanalyzer.jar /app/tools/
COPY --from=tools-downloader /app/tools/apktool.jar /app/tools/

# Copy application files
COPY patterns /app/patterns
COPY db/migrations /app/db/migrations

# Set proper permissions
RUN chmod +x /usr/local/bin/morf && \
    chmod +r /app/tools/*.jar

WORKDIR /app
EXPOSE 9092

# Get DATABASE_URL from host environment during build (optional)
ARG DATABASE_URL
ENV DATABASE_URL=${DATABASE_URL}

# Security: Run as non-root user
RUN useradd -m -u 1000 morfuser && \
    chown -R morfuser:morfuser /app && \
    chown -R morfuser:morfuser /tmp/morf

USER morfuser

# Security: Use seccomp profile for sandboxing
# The seccomp profile is applied via docker-compose.yml or docker run:
# docker run --security-opt seccomp=./seccomp/seccomp-apktool.json ...
# Or in docker-compose.yml: security_opt: - seccomp:./seccomp/seccomp-apktool.json

CMD ["morf", "server"]
