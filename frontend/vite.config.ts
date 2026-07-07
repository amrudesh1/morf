import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// Build output goes to dist/frontend so the existing frontend/Dockerfile + nginx
// (COPY dist/frontend -> /usr/share/nginx/html) work unchanged. Dev proxies /api
// to the local backend so `npm run dev` behaves like the nginx proxy.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    outDir: 'dist/frontend',
    emptyOutDir: true,
  },
  server: {
    port: 4200,
    proxy: {
      '/api': {
        target: 'http://localhost:9092',
        changeOrigin: true,
      },
    },
  },
})
