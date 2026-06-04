import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/dashboard/',
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8432',
      '/health': 'http://127.0.0.1:8432',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
