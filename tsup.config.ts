import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'cli/index': 'src/cli/index.ts',
  },
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  dts: { entry: { index: 'src/index.ts' } },
  sourcemap: true,
  clean: true,
  treeshake: true,
});
