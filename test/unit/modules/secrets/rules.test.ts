import { describe, expect, it } from 'vitest';

import type { Finding } from '../../../../src/core/finding.js';
import { scanTextForSecrets, secretsRules } from '../../../../src/modules/secrets/index.js';

function findingsFor(ruleId: string, path: string, text: string): Finding[] {
  return scanTextForSecrets(path, text).filter((f) => f.ruleId === ruleId);
}

// Every fake credential below is assembled by concatenation at test time so
// no realistic-looking key is ever committed (spec §14).

describe('secrets rule registry', () => {
  it('registers every v1 secrets rule', () => {
    const ids = secretsRules.map((r) => r.meta.id).sort();
    expect(ids).toEqual(
      [
        'SECRET-AIKEY-001',
        'SECRET-AWS-001',
        'SECRET-DBURL-001',
        'SECRET-ENTROPY-001',
        'SECRET-ENVFILE-001',
        'SECRET-GITHUB-001',
        'SECRET-GOOGLE-001',
        'SECRET-JWT-001',
        'SECRET-SESSION-001',
        'SECRET-PRIVKEY-001',
        'SECRET-SLACK-001',
        'SECRET-STRIPE-001',
      ].sort(),
    );
  });
});

describe('SECRET-AWS-001 (AWS access key id)', () => {
  it('detects a literal key and a concatenated key', () => {
    const key = 'AKIA' + 'IOSFODNN7EXAMPLE';
    expect(findingsFor('SECRET-AWS-001', 'a.js', `const k = "${key}";`)).toHaveLength(1);
    expect(
      findingsFor('SECRET-AWS-001', 'a.js', `const k = 'AKIA' + 'IOSFODNN7EXAMPLE';`),
    ).toHaveLength(1);
  });

  it('does not flag non-key text', () => {
    expect(findingsFor('SECRET-AWS-001', 'a.js', `const k = 'AKIA';`)).toHaveLength(0);
    expect(findingsFor('SECRET-AWS-001', 'a.js', `const k = 'AKIAIOSFODNN7EXAMPL';`)).toHaveLength(0);
  });
});

describe('SECRET-STRIPE-001 (Stripe secret key)', () => {
  it('detects live and test secret keys', () => {
    const live = 'sk_live_' + 'FAKEfakeFAKEfakeFAKE1234';
    const test = 'sk_test_' + 'FAKEfakeFAKEfakeFAKE1234';
    expect(findingsFor('SECRET-STRIPE-001', 'a.js', `pay("${live}")`)).toHaveLength(1);
    expect(findingsFor('SECRET-STRIPE-001', 'a.js', `pay("${test}")`)).toHaveLength(1);
  });

  it('does not flag short or publishable keys', () => {
    expect(findingsFor('SECRET-STRIPE-001', 'a.js', 'const k = "sk_live_short";')).toHaveLength(0);
    expect(
      findingsFor('SECRET-STRIPE-001', 'a.js', `const k = "pk_live_${'x'.repeat(24)}";`),
    ).toHaveLength(0);
  });
});

describe('SECRET-GITHUB-001 (GitHub token)', () => {
  it('detects ghp/gho/ghs tokens', () => {
    const token = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
    expect(findingsFor('SECRET-GITHUB-001', 'a.js', `auth("${token}")`)).toHaveLength(1);
  });

  it('does not flag short ghp_ strings', () => {
    expect(findingsFor('SECRET-GITHUB-001', 'a.js', 'const t = "ghp_tooShort";')).toHaveLength(0);
  });
});

describe('SECRET-SLACK-001 (Slack token)', () => {
  it('detects xoxb-style tokens', () => {
    const token = 'xoxb-' + '123456789012-abcdefghijklmnop';
    expect(findingsFor('SECRET-SLACK-001', 'a.js', `slack("${token}")`)).toHaveLength(1);
  });

  it('does not flag the bare prefix', () => {
    expect(findingsFor('SECRET-SLACK-001', 'a.js', 'const t = "xoxb";')).toHaveLength(0);
  });
});

describe('SECRET-GOOGLE-001 (Google API key)', () => {
  it('detects AIza keys', () => {
    const key = 'AIza' + 'SyFAKEfakeFAKEfakeFAKEfakeFAKEfake1';
    expect(key).toHaveLength(39);
    expect(findingsFor('SECRET-GOOGLE-001', 'a.js', `maps("${key}")`)).toHaveLength(1);
  });

  it('does not flag short AIza strings', () => {
    expect(findingsFor('SECRET-GOOGLE-001', 'a.js', 'const k = "AIzaShort";')).toHaveLength(0);
  });
});

describe('SECRET-AIKEY-001 (OpenAI/Anthropic-style key)', () => {
  it('detects sk- and sk-ant- keys', () => {
    const openai = 'sk-' + 'FAKEfakeFAKEfakeFAKEfake';
    const anthropic = 'sk-ant-' + 'FAKEfakeFAKEfakeFAKEfake';
    expect(findingsFor('SECRET-AIKEY-001', 'a.js', `ai("${openai}")`)).toHaveLength(1);
    expect(findingsFor('SECRET-AIKEY-001', 'a.js', `ai("${anthropic}")`).length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag short sk- strings', () => {
    expect(findingsFor('SECRET-AIKEY-001', 'a.js', 'const k = "sk-short";')).toHaveLength(0);
  });
});

describe('SECRET-PRIVKEY-001 (private key block)', () => {
  it('detects PEM private key headers', () => {
    expect(
      findingsFor('SECRET-PRIVKEY-001', 'key.pem', '-----BEGIN ' + 'PRIVATE KEY-----'),
    ).toHaveLength(1);
    expect(
      findingsFor('SECRET-PRIVKEY-001', 'key.pem', '-----BEGIN RSA ' + 'PRIVATE KEY-----'),
    ).toHaveLength(1);
  });

  it('does not flag public key headers', () => {
    expect(
      findingsFor('SECRET-PRIVKEY-001', 'key.pem', '-----BEGIN PUBLIC KEY-----'),
    ).toHaveLength(0);
  });
});

describe('SECRET-DBURL-001 (connection string with inline password)', () => {
  it('detects inline passwords in db urls', () => {
    expect(
      findingsFor('SECRET-DBURL-001', '.env', 'DATABASE_URL=postgres://admin:hunter2pass@db:5432/app'),
    ).toHaveLength(1);
    expect(
      findingsFor('SECRET-DBURL-001', 'a.js', 'const u = "mongodb+srv://root:p4ssw0rd@cluster/db";'),
    ).toHaveLength(1);
  });

  it('does not flag urls without a password or with placeholders', () => {
    expect(
      findingsFor('SECRET-DBURL-001', 'a.js', 'const u = "postgres://db.example.com:5432/app";'),
    ).toHaveLength(0);
    expect(
      findingsFor('SECRET-DBURL-001', 'a.js', 'const u = `postgres://admin:${password}@db/app`;'),
    ).toHaveLength(0);
    expect(
      findingsFor(
        'SECRET-DBURL-001',
        'README.md',
        'mongodb://<username>:<password>@cluster.example.com/db',
      ),
    ).toHaveLength(0);
  });
});

describe('SECRET-JWT-001 (hardcoded JWT secret)', () => {
  it('detects jwt secrets assigned from string literals', () => {
    expect(
      findingsFor('SECRET-JWT-001', 'a.js', 'const JWT_SECRET = "super-secret-jwt-signing-key";'),
    ).toHaveLength(1);
    expect(
      findingsFor('SECRET-JWT-001', 'a.js', 'const jwtSecret = "another-secret-value";'),
    ).toHaveLength(1);
  });

  it('does not flag env-sourced jwt secrets', () => {
    expect(
      findingsFor('SECRET-JWT-001', 'a.js', 'const JWT_SECRET = process.env.JWT_SECRET;'),
    ).toHaveLength(0);
  });
});

describe('SECRET-ENTROPY-001 (generic high-entropy assignment)', () => {
  it('flags high-entropy literals assigned to secret-like names with low confidence', () => {
    const value = 'aB3dE5gH7jK9mN1pQ4sU6wX8';
    const found = findingsFor('SECRET-ENTROPY-001', 'a.js', `const apiKey = "${value}";`);
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe('low');
  });

  it('ignores low-entropy values and non-secret variable names', () => {
    expect(
      findingsFor('SECRET-ENTROPY-001', 'a.js', 'const apiKey = "aaaaaaaaaaaaaaaaaaaaaaaa";'),
    ).toHaveLength(0);
    expect(
      findingsFor('SECRET-ENTROPY-001', 'a.js', 'const banner = "aB3dE5gH7jK9mN1pQ4sU6wX8";'),
    ).toHaveLength(0);
  });
});

describe('SECRET-ENVFILE-001 (committed .env file)', () => {
  it('flags .env and .env.<stage> files', () => {
    expect(findingsFor('SECRET-ENVFILE-001', '.env', 'X=1')).toHaveLength(1);
    expect(findingsFor('SECRET-ENVFILE-001', '.env.production', 'X=1')).toHaveLength(1);
    expect(findingsFor('SECRET-ENVFILE-001', 'config/.env', 'X=1')).toHaveLength(1);
  });

  it('does not flag .env.example or similarly named source files', () => {
    expect(findingsFor('SECRET-ENVFILE-001', '.env.example', 'X=')).toHaveLength(0);
    expect(findingsFor('SECRET-ENVFILE-001', 'src/env.ts', 'export const env = {};')).toHaveLength(0);
  });
});

describe('masking invariant', () => {
  it('no finding ever contains a raw secret in any field', () => {
    const raw = 'AKIA' + 'IOSFODNN7EXAMPLE';
    const findings = scanTextForSecrets('a.js', `const k = "${raw}";`);
    expect(findings.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(raw);
    expect(serialized).toContain('AKIA****');
  });

  it('remediation always tells the user to rotate the credential', () => {
    const findings = scanTextForSecrets('a.js', `const k = "${'AKIA' + 'IOSFODNN7EXAMPLE'}";`);
    expect(findings[0]?.remediation).toMatch(/rotate/i);
    expect(findings[0]?.remediation).toMatch(/git history/i);
  });
});
