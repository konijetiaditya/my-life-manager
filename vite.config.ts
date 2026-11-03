import { defineConfig } from 'vitest/config';

// Everything is bundled locally. The app never loads code, fonts or images from the internet.
export default defineConfig({
  base: './',
  build: {
    target: 'chrome90',
    outDir: 'dist',
    sourcemap: false,
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 2500,
    rollupOptions: {
      // Some Android WebViews do not know the .mjs type; serve everything as plain .js.
      output: { assetFileNames: (a) => (a.names?.[0]?.endsWith('.mjs') ? 'assets/[name]-[hash].js' : 'assets/[name]-[hash][extname]') },
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 60000,
  },
});
