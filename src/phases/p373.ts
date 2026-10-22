/**
 * Phase 373. CDN script tags without SRI.
 * Off unless FULLSHIELD_EXPERIMENTAL_SRITAG=1.
 * Does not fetch the URL.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SRITAG';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SriTagFinding {
  ruleId: 'CONFIG-SRI-001';
  severity: 'low';
  file: string;
  url: string;
  message: string;
}

function htmlTags(html: string): SriTagFinding[] {
  const stripped = html.replace(/<!--[\s\S]*?-->/g, '');
  const findings: Array<{ url: string }> = [];
  const tags = stripped.matchAll(/<(script|link)\b[^>]*>/gi);
  for (const tag of tags) {
    const raw = tag[0] ?? '';
    const kind = (tag[1] ?? '').toLowerCase();
    if (kind === 'link' && !/\brel\s*=\s*['"]stylesheet['"]/i.test(raw)) {
      continue;
    }
    const urlMatch = /\b(?:src|href)\s*=\s*['"]([^'"]+)['"]/i.exec(raw);
    const url = urlMatch?.[1];
    if (url === undefined) {
      continue;
    }
    if (/\bintegrity\s*=/i.test(raw)) {
      continue;
    }
    findings.push({ url });
  }
  return findings.map((item) => ({
    ruleId: 'CONFIG-SRI-001',
    severity: 'low',
    file: '',
    url: item.url,
    message: '',
  }));
}

function attrValue(attr: TSESTree.JSXAttribute): string | null {
  if (attr.value === null) {
    return '';
  }
  if (attr.value.type === 'Literal' && typeof attr.value.value === 'string') {
    return attr.value.value;
  }
  return null;
}

function jsxTags(source: string): Array<{ url: string }> {
  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: false, range: false, jsx: true });
  } catch {
    return [];
  }
  const found: Array<{ url: string }> = [];
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'JSXOpeningElement') {
      const name = node.name.type === 'JSXIdentifier' ? node.name.name : '';
      if (name === 'script' || name === 'link') {
        let url: string | null = null;
        let integrity = false;
        let stylesheet = name === 'script';
        for (const attr of node.attributes) {
          if (attr.type !== 'JSXAttribute' || attr.name.type !== 'JSXIdentifier') {
            continue;
          }
          const key = attr.name.name;
          const value = attrValue(attr);
          if (key === 'integrity') {
            integrity = true;
          }
          if (key === 'src' || key === 'href') {
            url = value;
          }
          if (key === 'rel' && value === 'stylesheet') {
            stylesheet = true;
          }
        }
        if (stylesheet && url !== null && !integrity) {
          found.push({ url });
        }
      }
    }
    const record = node as unknown as Record<string, unknown>;
    for (const value of Object.values(record)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'object' && item !== null && 'type' in item) {
            visit(item as TSESTree.Node);
          }
        }
      } else if (typeof value === 'object' && value !== null && 'type' in value) {
        visit(value as TSESTree.Node);
      }
    }
  };
  visit(ast);
  return found;
}

function classify(url: string): boolean {
  if (url.startsWith('https:') || url.startsWith('http:')) {
    return true;
  }
  return false;
}

export function sriTags(file: string, source: string, kind: 'html' | 'jsx', allowHosts: readonly string[] = []): SriTagFinding[] {
  if (!enabled()) {
    return [];
  }
  const urls = kind === 'html' ? htmlTags(source).map((item) => item.url) : jsxTags(source).map((item) => item.url);
  const findings: SriTagFinding[] = [];
  for (const url of urls) {
    if (!classify(url)) {
      continue;
    }
    let host = '';
    try {
      host = new URL(url).host;
    } catch {
      continue;
    }
    if (allowHosts.includes(host)) {
      continue;
    }
    findings.push({
      ruleId: 'CONFIG-SRI-001',
      severity: 'low',
      file,
      url,
      message: `${file} loads ${url} without an integrity attribute. A nonce is not SRI.`,
    });
  }
  return findings;
}
