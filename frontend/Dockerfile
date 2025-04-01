# Stage 1: Build Angular app
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:alpine
# Copy the built app and ensure assets are included
COPY --from=builder /app/dist/frontend /usr/share/nginx/html
# Explicitly copy assets to ensure they're available
COPY --from=builder /app/src/assets /usr/share/nginx/html/assets
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
