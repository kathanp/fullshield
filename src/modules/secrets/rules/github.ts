import { everyMatch } from '../mask.js';
import { secretCheckEnabled } from '../precision.js';
import type { SecretsRule } from '../types.js';

const CLASSIC = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g;
const FINE_GRAINED = /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g;

export const githubRule: SecretsRule = {
  meta: {
    id: 'SECRET-GITHUB-001',
    title: 'Hardcoded GitHub token',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    const patterns = secretCheckEnabled() ? [CLASSIC, FINE_GRAINED] : [CLASSIC];
    ctx.lines.forEach((line, index) => {
      for (const pattern of patterns) {
        for (const match of everyMatch(pattern, line)) {
          ctx.report({ line: index + 1, secret: match[0] });
        }
      }
    });
  },
};
