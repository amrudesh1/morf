# Stage 1: Build the Go binary
FROM golang:1.21.7 AS go-builder
WORKDIR /app
COPY . .
RUN go mod download
ENV GOARCH=arm64 GOOS=linux CGO_ENABLED=0
RUN go build -v -o morf .

# Stage 2: Final image with all tools
FROM debian:bullseye-slim
ARG JDK_VERSION=11

# Install required tools and cleanup in one layer
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
    chmod -R 777 /tmp/morf

# Copy the binary from builder
COPY --from=go-builder /app/morf /usr/local/bin/morf

# Copy necessary files

COPY tools/apkanalyzer.jar /app/tools/
COPY tools/apktool.jar /app/tools/

COPY patterns /app/patterns
COPY db/migrations /app/db/migrations


# Set proper permissions
RUN chmod +x /usr/local/bin/morf

WORKDIR /app
EXPOSE 9092

# Get DATABASE_URL from host environment during build
ARG DATABASE_URL
ENV DATABASE_URL=${DATABASE_URL}

CMD ["morf", "server"]
