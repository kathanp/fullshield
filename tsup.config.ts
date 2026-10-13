import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'cli/index': 'src/cli/index.ts',
    'runtime/index': 'src/runtime/index.ts',
    'runtime/express': 'src/runtime/express.ts',
    'runtime/fastify': 'src/runtime/fastify.ts',
  },
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  dts: { entry: { index: 'src/index.ts' } },
  sourcemap: true,
  clean: true,
  treeshake: true,
  splitting: false,
});
