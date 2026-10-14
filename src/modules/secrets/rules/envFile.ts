import type { SecretsRule } from '../types.js';

const ENV_FILE = /^\.env(\..+)?$/;

export const envFileRule: SecretsRule = {
  meta: {
    id: 'SECRET-ENVFILE-001',
    title: 'Committed .env file',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-312',
  },
  check(ctx) {
    const base = ctx.path.split('/').pop() ?? ctx.path;
    ENV_FILE.lastIndex = 0;
    if (ENV_FILE.test(base) && base !== '.env.example' && base !== '.env.backup') {
      ctx.report({
        line: 1,
        message:
          `${ctx.path} is tracked in the repository. .env files hold live credentials and must never be committed.`,
      });
    }
  },
};
