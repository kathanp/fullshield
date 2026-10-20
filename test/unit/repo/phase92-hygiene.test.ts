import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');

interface SchemaError {
  instancePath?: string;
  message?: string;
}

interface ValidateFn {
  (data: unknown): boolean;
  errors?: SchemaError[] | null;
}

interface AjvLike {
  compile(schema: object): ValidateFn;
}

interface YamlModule {
  parse(text: string): unknown;
}

const ACCURACY_CLAIM =
  /\b(more|less) accurate\b|\boutperforms?\b|\b(higher|lower) (precision|recall)\b|\bfewer false positives\b|\bmore false positives\b|\bcatches more\b/i;

function loadAjv(): new (options: { allErrors: boolean; strict: boolean }) => AjvLike {
  const nested = createRequire(require.resolve('ajv-formats/package.json'));
  const loaded: unknown = nested('ajv');
  if (typeof loaded === 'function') return loaded as new (options: { allErrors: boolean; strict: boolean }) => AjvLike;
  if (typeof loaded === 'object' && loaded !== null && 'default' in loaded) {
    const ctor = loaded.default;
    if (typeof ctor === 'function') {
      return ctor as new (options: { allErrors: boolean; strict: boolean }) => AjvLike;
    }
  }
  throw new Error('ajv constructor missing');
}

function loadYaml(): YamlModule {
  const loaded: unknown = require('yaml');
  if (typeof loaded === 'object' && loaded !== null && 'parse' in loaded && typeof loaded.parse === 'function') {
    return loaded as YamlModule;
  }
  throw new Error('yaml parse missing');
}

const yaml = loadYaml();
const ajv = new (loadAjv())({ allErrors: true, strict: false });
const formSchema = JSON.parse(readFileSync(join(root, 'test/schemas/github-issue-forms.json'), 'utf8')) as object;
const configSchema = JSON.parse(readFileSync(join(root, 'test/schemas/github-issue-config.json'), 'utf8')) as object;
const validateForm = ajv.compile(formSchema);
const validateConfig = ajv.compile(configSchema);

function parseYamlFile(path: string): unknown {
  return yaml.parse(readFileSync(path, 'utf8'));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function labelsOf(data: unknown): string[] {
  if (!isRecord(data) || !Array.isArray(data.body)) return [];
  const labels: string[] = [];
  for (const item of data.body) {
    if (!isRecord(item)) continue;
    const attributes = item.attributes;
    if (!isRecord(attributes)) continue;
    if (typeof attributes.label === 'string') labels.push(attributes.label);
  }
  return labels;
}

function localLinkTargets(markdown: string): string[] {
  const targets: string[] = [];
  const pattern = /\[[^\]]*\]\(([^)\s]+)\)/g;
  for (const match of markdown.matchAll(pattern)) {
    const href = match[1];
    if (href === undefined || /^(https?:|mailto:)/.test(href)) continue;
    const pathOnly = href.split('#')[0] ?? '';
    if (pathOnly !== '') targets.push(pathOnly);
  }
  return targets;
}

function unresolvedLocalLinks(filePath: string, markdown: string): string[] {
  const base = dirname(filePath);
  return localLinkTargets(markdown).filter((href) => !existsSync(resolve(base, href)));
}

function matrixCheckNames(ci: string): string[] {
  const osMatch = /os:\s*\[([^\]]+)\]/.exec(ci);
  const nodeMatch = /node:\s*\[([^\]]+)\]/.exec(ci);
  if (osMatch?.[1] === undefined || nodeMatch?.[1] === undefined) return [];
  const oses = osMatch[1].split(',').map((item) => item.trim());
  const nodes = nodeMatch[1].split(',').map((item) => item.trim());
  const names: string[] = [];
  for (const os of oses) {
    for (const node of nodes) names.push(`verify (${os}, node ${node})`);
  }
  return names;
}

describe('Phase 92 repository hygiene', () => {
  const formFiles = ['false-positive.yml', 'false-negative.yml', 'bug.yml', 'new-rule.yml'];

  it('validates issue forms against the vendored GitHub schema', () => {
    for (const name of formFiles) {
      const data = parseYamlFile(join(root, '.github/ISSUE_TEMPLATE', name));
      expect(validateForm(data), `${name} ${JSON.stringify(validateForm.errors)}`).toBe(true);
    }
  });

  it('rejects an issue form that is missing a name and uses an unknown type', () => {
    const data = parseYamlFile(join(root, 'test/fixtures/phase92/invalid-form.yml'));
    expect(validateForm(data)).toBe(false);
  });

  it('asks for rule ID, minimal code, version, and expected on false positive and false negative', () => {
    for (const name of ['false-positive.yml', 'false-negative.yml']) {
      const labels = labelsOf(parseYamlFile(join(root, '.github/ISSUE_TEMPLATE', name)));
      expect(labels.some((label) => /rule id/i.test(label)), name).toBe(true);
      expect(labels.some((label) => /minimal code/i.test(label)), name).toBe(true);
      expect(labels.some((label) => /^version$/i.test(label)), name).toBe(true);
      expect(labels.some((label) => /^expected$/i.test(label)), name).toBe(true);
    }
  });

  it('turns blank issues off and points vulnerabilities at SECURITY.md', () => {
    const path = join(root, '.github/ISSUE_TEMPLATE/config.yml');
    const data = parseYamlFile(path);
    expect(validateConfig(data), JSON.stringify(validateConfig.errors)).toBe(true);
    expect(data).toMatchObject({ blank_issues_enabled: false });
    expect(readFileSync(path, 'utf8')).toContain('SECURITY.md');
  });

  it('rejects a contact link whose url is not http(s)', () => {
    const data = parseYamlFile(join(root, 'test/fixtures/phase92/invalid-config.yml'));
    expect(validateConfig(data)).toBe(false);
  });

  it('resolves local links in the hygiene docs', () => {
    for (const name of ['use-with-other-tools.md', 'branch-protection.md']) {
      const path = join(root, 'docs', name);
      const text = readFileSync(path, 'utf8');
      expect(unresolvedLocalLinks(path, text), name).toEqual([]);
      expect(localLinkTargets(text).length, name).toBeGreaterThan(0);
    }
  });

  it('reports a local link that does not exist', () => {
    const path = join(root, 'test/fixtures/phase92/broken-link.md');
    expect(unresolvedLocalLinks(path, readFileSync(path, 'utf8'))).toEqual(['./not-a-real-page.md']);
  });

  it('documents commands for Semgrep, OSV-Scanner, npm audit, Gitleaks, and ingest', () => {
    const text = readFileSync(join(root, 'docs/use-with-other-tools.md'), 'utf8');
    expect(text).toContain('semgrep scan --json');
    expect(text).toContain('osv-scanner scan');
    expect(text).toContain('--format json');
    expect(text).toContain('npm audit --json');
    expect(text).toContain('gitleaks git --report-format sarif');
    expect(text).toContain('fullshield ingest');
    expect(ACCURACY_CLAIM.test(text)).toBe(false);
  });

  it('flags a sentence that claims another tool is more accurate', () => {
    const text = readFileSync(join(root, 'test/fixtures/phase92/accuracy-claim.md'), 'utf8');
    expect(ACCURACY_CLAIM.test(text)).toBe(true);
    expect(ACCURACY_CLAIM.test('Run Semgrep, then pass the file to fullshield ingest.')).toBe(false);
  });

  it('lists the six matrix check names for a human to set', () => {
    const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
    const names = matrixCheckNames(ci);
    expect(names).toEqual([
      'verify (ubuntu-24.04, node 22)',
      'verify (ubuntu-24.04, node 24)',
      'verify (macos-latest, node 22)',
      'verify (macos-latest, node 24)',
      'verify (windows-latest, node 22)',
      'verify (windows-latest, node 24)',
    ]);
    const doc = readFileSync(join(root, 'docs/branch-protection.md'), 'utf8');
    for (const name of names) expect(doc).toContain(name);
    const missingOne = names.slice(1).join('\n');
    expect(names.every((name) => missingOne.includes(name))).toBe(false);
  });

  it('marks the Section 33 issue-templates item done', () => {
    const spec = readFileSync(join(root, 'SECURITY_SCANNER_SPEC.md'), 'utf8');
    expect(spec).toContain(
      '[ X ] Issue templates for bug, false positive, missed attack, and new rule (Section 15).',
    );
  });
});
