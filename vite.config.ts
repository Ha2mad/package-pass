import { defineConfig } from 'vite';

export default defineConfig({
  // Relative by default so the build works from any static host or sub-path.
  base: process.env.BASE_PATH || './',
  oxc: { jsx: { runtime: 'automatic', importSource: 'preact' } },
  test: { environment: 'node', include: ['tests/**/*.test.{ts,tsx}'] },
} as never);
