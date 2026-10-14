import type { Finding, FixProposal } from '../core/finding.js';
import { unifiedDiff } from './diff.js';

export function proposeFix(finding: Finding, source: string): FixProposal | undefined {
  const file = finding.file ?? '';
  if (finding.ruleId === 'CONFIG-HELMET-001') return helmetFix(file, source);
  if (finding.ruleId === 'CONFIG-BODYLIMIT-001') return bodyLimitFix(file, source);
  if (finding.ruleId === 'SAST-CRYPTO-001') return cryptoFix(file, source);
  if (finding.ruleId === 'SECRET-ENVFILE-001') return gitignoreFix(file, source);
  if (finding.fix !== undefined) return finding.fix;
  if (finding.ruleId.startsWith('SECRET-') && finding.ruleId !== 'SECRET-ENVFILE-001') {
    return secretEnvFix(file, source, finding);
  }
  return undefined;
}

function helmetFix(file: string, source: string): FixProposal | undefined {
  if (/helmet\s*\(/.test(source)) return undefined;
  let after = source;
  if (!/require\(\s*['"]helmet['"]\s*\)|from\s+['"]helmet['"]/.test(after)) {
    after = `const helmet = require('helmet');\n${after}`;
  }
  if (!/app\.use\(\s*helmet\s*\(\s*\)\s*\)/.test(after)) {
    after = after.replace(/const app = express\(\s*\);/, (m) => `${m}\napp.use(helmet());`);
  }
  if (after === source) return undefined;
  return { kind: 'config-add', safe: false, diff: unifiedDiff(file, source, after) };
}

function bodyLimitFix(file: string, source: string): FixProposal | undefined {
  if (!/express\.json\(\s*\)/.test(source)) return undefined;
  const after = source.replace(/express\.json\(\s*\)/g, "express.json({ limit: '100kb' })");
  return { kind: 'config-add', safe: true, diff: unifiedDiff(file, source, after) };
}

function cryptoFix(file: string, source: string): FixProposal | undefined {
  if (!/Math\.random\(\)/.test(source)) return undefined;
  let after = source;
  if (!/require\(\s*['"]crypto['"]\s*\)|from\s+['"]crypto['"]/.test(after)) {
    after = `const crypto = require('crypto');\n${after}`;
  }
  after = after.replace(
    /Math\.random\(\)\.toString\(\s*36\s*\)(?:\.slice\(\s*2\s*\))?/g,
    'crypto.randomUUID()',
  );
  if (after === source) return undefined;
  return { kind: 'code-patch', safe: true, diff: unifiedDiff(file, source, after) };
}

function gitignoreFix(file: string, source: string): FixProposal | undefined {
  const target = file.endsWith('.gitignore') ? file : '.gitignore';
  if (/(^|\n)\.env(\n|$)/.test(source)) return undefined;
  const after = source.length === 0 || source.endsWith('\n') ? `${source}.env\n` : `${source}\n.env\n`;
  return { kind: 'config-add', safe: true, diff: unifiedDiff(target, source, after) };
}

function secretEnvFix(file: string, source: string, finding: Finding): FixProposal | undefined {
  const envName = envNameFor(finding.ruleId);
  // Replace a quoted/concatenated assignment on the finding line only.
  const lines = source.split('\n');
  const idx = (finding.line ?? 1) - 1;
  const line = lines[idx];
  if (line === undefined) return undefined;
  const replaced = line.replace(
    /=\s*(?:'[^']*'|"[^"]*"|(?:'[^']*'|"[^"]*"|\s|\+)+\s*$)/,
    `= process.env.${envName} /* TODO: rotate this key; it remains in git history */`,
  );
  if (replaced === line) return undefined;
  const afterLines = [...lines];
  afterLines[idx] = replaced;
  return { kind: 'code-patch', safe: false, diff: unifiedDiff(file, source, afterLines.join('\n')) };
}

function envNameFor(ruleId: string): string {
  if (ruleId.includes('AWS')) return 'AWS_ACCESS_KEY_ID';
  if (ruleId.includes('STRIPE')) return 'STRIPE_SECRET_KEY';
  if (ruleId.includes('JWT')) return 'JWT_SECRET';
  if (ruleId.includes('GITHUB')) return 'GITHUB_TOKEN';
  if (ruleId.includes('SLACK')) return 'SLACK_TOKEN';
  if (ruleId.includes('GOOGLE')) return 'GOOGLE_API_KEY';
  if (ruleId.includes('AI')) return 'AI_API_KEY';
  if (ruleId.includes('DBURL')) return 'DATABASE_URL';
  return 'SECRET';
}

/** Apply a single-file unified diff produced by `unifiedDiff`. */
export function applyUnifiedDiff(source: string, diff: string): string {
  const plus = diff
    .split('\n')
    .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
    .map((line) => line.slice(1));
  if (plus.length === 0) return source;
  return plus.join('\n');
}
