import { defineConfig } from 'vite';

// Bundles the Node CLI (src/cli.ts) into a single ESM file with fflate inlined.
export default defineConfig({
  build: {
    ssr: 'src/cli.ts',
    outDir: 'dist-cli',
    emptyOutDir: true,
    target: 'node20',
    rollupOptions: { output: { entryFileNames: 'cli.js', banner: '#!/usr/bin/env node' } },
  },
  ssr: { noExternal: true },
});
