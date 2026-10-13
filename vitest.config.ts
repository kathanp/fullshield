import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts', 'test/e2e/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // src/cli/index.ts is the executable entry (shebang + parse call only);
      // it is exercised by the e2e tests against the built binary.
      exclude: ['src/cli/index.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
      // Spec 0.1: lines >= 80%, branches >= 75% for src/ (Core).
      // NOTE: the spec's `src/modules/**` >= 85% threshold will be added in
      // Phase 2 when the first module exists (an empty glob fails the run).
      thresholds: {
        lines: 80,
        branches: 75,
      },
    },
  },
});
