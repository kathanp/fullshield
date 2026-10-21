import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { credFilesEnabled } from './experimental.js';
import { foldStringConcat, maskSecret } from './mask.js';
import { applySecretPrecision, secretCheckEnabled } from './precision.js';
import { aiKeyRule } from './rules/aiKey.js';
import { awsRule } from './rules/aws.js';
import { credFilePresenceRules, credFileRules } from './rules/credFiles.js';
import { dbUrlRule } from './rules/dbUrl.js';
import { entropyRule } from './rules/entropy.js';
import { envFileRule } from './rules/envFile.js';
import { githubRule } from './rules/github.js';
import { googleRule } from './rules/google.js';
import { jwtSecretRule } from './rules/jwtSecret.js';
import { privateKeyRule } from './rules/privateKey.js';
import { sessionSecretRule } from './rules/sessionSecret.js';
import { slackRule } from './rules/slack.js';
import { stripeRule } from './rules/stripe.js';
import type { SecretHit, SecretsRule } from './types.js';

export const secretsRules: readonly SecretsRule[] = [
  awsRule,
  stripeRule,
  githubRule,
  slackRule,
  googleRule,
  aiKeyRule,
  privateKeyRule,
  dbUrlRule,
  jwtSecretRule,
  sessionSecretRule,
  entropyRule,
  envFileRule,
];

const REMEDIATION =
  'Rotate this credential immediately, then load it from an environment variable or a secret manager. ' +
  'Removing it from the code is NOT enough: it remains visible in git history.';

function hitsForRules(path: string, text: string, rules: readonly SecretsRule[]): SecretHit[] {
  const rawLines = text.split(/\r?\n/);
  const lines = rawLines.map(foldStringConcat);
  const hits: SecretHit[] = [];
  for (const rule of rules) {
    rule.check({
      path,
      lines,
      rawLines,
      report: ({ line, secret, message }) => {
        const masked = secret !== undefined ? maskSecret(secret) : undefined;
        const finding: Finding = {
          id: makeFindingId(rule.meta.id, path, `${line}|${masked ?? 'file'}`),
          ruleId: rule.meta.id,
          module: 'secrets',
          title: rule.meta.title,
          severity: rule.meta.severity,
          confidence: rule.meta.confidence,
          cwe: rule.meta.cwe,
          file: path,
          line,
          snippet: masked,
          message: message ?? `${rule.meta.title}${masked !== undefined ? ` (${masked})` : ''}.`,
          remediation: REMEDIATION,
        };
        if (secretCheckEnabled()) {applySecretPrecision(path, finding, secret);}
        hits.push({ finding, secret });
      },
    });
  }
  return hits;
}

/** Scan one file's text with every secrets rule. Secrets are always masked. */
export function scanTextForSecretHits(path: string, text: string): SecretHit[] {
  const rules = credFilesEnabled() ? [...secretsRules, ...credFileRules] : secretsRules;
  return hitsForRules(path, text, rules);
}

/** Scan one file's text with every secrets rule. Secrets are always masked. */
export function scanTextForSecrets(path: string, text: string): Finding[] {
  return scanTextForSecretHits(path, text).map((hit) => hit.finding);
}

/** Skip files larger than 1 MiB or containing NUL bytes (binary). */
const MAX_FILE_SIZE = 1024 * 1024;

export const secretsModule: ScanModule = {
  name: 'secrets',
  async run(ctx) {
    const findings: Finding[] = [];
    for (const rel of ctx.files) {
      let text: string;
      try {
        text = await readFile(join(ctx.cwd, rel), 'utf8');
      } catch {
        continue; // unreadable file: nothing to scan
      }
      if (text.length > MAX_FILE_SIZE || text.includes('\u0000')) {
        if (credFilesEnabled()) {findings.push(...hitsForRules(rel, '', credFilePresenceRules).map((hit) => hit.finding));}
        continue;
      }
      findings.push(...scanTextForSecrets(rel, text));
    }
    return findings;
  },
};
