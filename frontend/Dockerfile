# syntax=docker/dockerfile:1.6
# Stage 1: Build Angular app.
# BuildKit cache mounts speed up reinstalls when only source changes.
FROM --platform=$BUILDPLATFORM node:20-alpine AS builder
WORKDIR /app

# Install dependencies first (cached layer when package.json hasn't changed).
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

# Copy sources and build with prod optimizations.
COPY . .
RUN npm run build -- --configuration production

# Stage 2: Serve static bundle with nginx (alpine for size).
FROM nginx:1.27-alpine
# Angular's prod build emits assets into the dist root; one COPY suffices.
COPY --from=builder /app/dist/frontend /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --quiet --spider http://localhost/ || exit 1
CMD ["nginx", "-g", "daemon off;"]
