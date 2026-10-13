import type { SecretsRule } from '../types.js';

const PATTERN = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g;

export const githubRule: SecretsRule = {
  meta: {
    id: 'SECRET-GITHUB-001',
    title: 'Hardcoded GitHub token',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    ctx.lines.forEach((line, index) => {
      for (const match of line.matchAll(PATTERN)) {
        ctx.report({ line: index + 1, secret: match[0] });
      }
    });
  },
};
