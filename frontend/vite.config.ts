import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // Wails embeds the entire dist/ directory; keep it small.
    outDir: 'dist',
    emptyOutDir: true,
    // Inline small assets to avoid extra network requests inside the Wails
    // webview (which does not cache aggressively).
    assetsInlineLimit: 4096,
  },
  // In wails dev mode the Go backend acts as a proxy; Vite dev server
  // serves the frontend on :34115 and Wails bridges the two.
  server: {
    port: 34115,
    strictPort: true,
  },
});
