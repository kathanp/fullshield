import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'cli/index': 'src/cli/index.ts',
    'runtime/index': 'src/runtime/index.ts',
    'runtime/express': 'src/runtime/express.ts',
    'runtime/fastify': 'src/runtime/fastify.ts',
    'runtime/rasp': 'src/runtime/rasp/index.ts',
    'runtime/register': 'src/runtime/register.ts',
    'runtime/auto': 'src/runtime/auto.ts',
    'runtime/rasp/loader': 'src/runtime/rasp/loader.ts',
    supply: 'src/supply/index.ts',
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
