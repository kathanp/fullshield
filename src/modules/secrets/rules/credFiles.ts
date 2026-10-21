import type { SecretsRule } from '../types.js';

const baseName = (path: string): string => path.split('/').pop() ?? path;

/** A registry or file secret that is a real literal, not an env interpolation. */
function literalValue(raw: string | undefined): string | undefined {
  if (raw === undefined) {return undefined;}
  let value = raw.trim();
  if (
    (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
    (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
  ) {
    value = value.slice(1, -1);
  }
  if (value.length === 0 || value.startsWith('${')) {return undefined;}
  return value;
}

export const npmrcRule: SecretsRule = {
  meta: {
    id: 'SECRET-FILE-002',
    title: 'npm credential in .npmrc',
    severity: 'critical',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    if (baseName(ctx.path) !== '.npmrc') {return;}
    ctx.lines.forEach((line, index) => {
      if (line.trimStart().startsWith('#')) {return;}
      const token = line.match(/(^|[^\w])_authToken=\s*(\S*)/);
      const auth = token === null ? line.match(/(^|[^\w])_auth=\s*(\S*)/) : null;
      const secret = literalValue(token?.[2] ?? auth?.[2]);
      if (secret === undefined) {return;}
      ctx.report({
        line: index + 1,
        secret,
        message: '.npmrc contains a literal registry credential.',
      });
    });
  },
};

export const dockerConfigRule: SecretsRule = {
  meta: {
    id: 'SECRET-FILE-003',
    title: 'Docker registry credential in config.json',
    severity: 'critical',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    if (baseName(ctx.path) !== 'config.json') {return;}
    const text = ctx.lines.join('\n');
    if (!text.includes('"auths"')) {return;}
    const match = text.match(/"auth"\s*:\s*"([^"]*)"/);
    const secret = literalValue(match?.[1]);
    if (secret === undefined) {return;}
    const line = ctx.lines.findIndex((row) => row.includes('"auth"'));
    ctx.report({
      line: line < 0 ? 1 : line + 1,
      secret,
      message: 'Docker config.json contains a registry auth value.',
    });
  },
};

export const kubeconfigRule: SecretsRule = {
  meta: {
    id: 'SECRET-FILE-004',
    title: 'kubeconfig credential',
    severity: 'critical',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    const text = ctx.lines.join('\n');
    if (!text.includes('apiVersion: v1') || !text.includes('kind: Config')) {return;}
    ctx.lines.forEach((line, index) => {
      const match = line.match(/^\s*(token|client-key-data):\s*(\S+)\s*$/);
      const secret = literalValue(match?.[2]);
      if (secret === undefined) {return;}
      ctx.report({
        line: index + 1,
        secret,
        message: 'kubeconfig contains a token or client key.',
      });
    });
  },
};

export const tfstateRule: SecretsRule = {
  meta: {
    id: 'SECRET-FILE-005',
    title: 'Committed Terraform state',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-312',
  },
  check(ctx) {
    const base = baseName(ctx.path);
    if (!base.endsWith('.tfstate') && !base.endsWith('.tfstate.backup')) {return;}
    ctx.report({
      line: 1,
      message: `${ctx.path} is Terraform state and holds secrets.`,
    });
  },
};

export const serviceAccountRule: SecretsRule = {
  meta: {
    id: 'SECRET-FILE-006',
    title: 'Cloud service-account key',
    severity: 'critical',
    confidence: 'high',
    cwe: 'CWE-798',
  },
  check(ctx) {
    const text = ctx.lines.join('\n');
    if (!/"type"\s*:\s*"service_account"/.test(text)) {return;}
    const match = text.match(/"private_key"\s*:\s*"([^"]*)"/);
    const secret = literalValue(match?.[1]);
    if (secret === undefined) {return;}
    const line = ctx.lines.findIndex((row) => row.includes('"private_key"'));
    ctx.report({
      line: line < 0 ? 1 : line + 1,
      secret,
      message: 'JSON service-account key is committed.',
    });
  },
};

export const keyFileRule: SecretsRule = {
  meta: {
    id: 'SECRET-FILE-007',
    title: 'Committed private key file',
    severity: 'critical',
    confidence: 'high',
    cwe: 'CWE-321',
  },
  check(ctx) {
    const base = baseName(ctx.path);
    if (base.endsWith('.pub')) {return;}
    const hit =
      base === 'id_rsa' ||
      base === 'id_ed25519' ||
      base.endsWith('.p12') ||
      base.endsWith('.pfx') ||
      base.endsWith('.keystore');
    if (!hit) {return;}
    ctx.report({
      line: 1,
      message: `${ctx.path} is a private key file and must not be committed.`,
    });
  },
};

/** Text and filename rules for phase 105. Not part of the default secretsRules list. */
export const credFileRules: readonly SecretsRule[] = [
  npmrcRule,
  dockerConfigRule,
  kubeconfigRule,
  tfstateRule,
  serviceAccountRule,
  keyFileRule,
];

/** Filename rules that must run even when the file is binary or over the size cap. */
export const credFilePresenceRules: readonly SecretsRule[] = [tfstateRule, keyFileRule];
