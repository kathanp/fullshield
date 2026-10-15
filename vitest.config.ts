import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts', 'test/e2e/**/*.test.ts'],
    // Coverage + RASP p95 + 100k flood tests contend for the same cores.
    pool: 'forks',
    poolOptions: {
      forks: { minForks: 1, maxForks: 4 },
    },
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // src/cli/index.ts is the executable entry (shebang + parse call only);
      // it is exercised by the e2e tests against the built binary.
      exclude: ['src/cli/index.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
      // Spec 0.1: lines >= 80%, branches >= 75% for src/ (Core).
      // Branches 80% (actual coverage is higher) so PRs have headroom.
      // src/modules/** >= 85% (active since Phase 2).
      thresholds: {
        lines: 80,
        branches: 80,
        'src/modules/**/*.ts': {
          lines: 85,
          branches: 75,
        },
        'src/fixer/**/*.ts': {
          lines: 90,
        },
        'src/cli/program.ts': {
          lines: 80,
        },
        'src/reporters/sarif.ts': {
          branches: 75,
        },
      },
    },
  },
});
