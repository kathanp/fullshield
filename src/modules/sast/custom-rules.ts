import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

import { ConfigError } from '../../core/config.js';
import { isSeverity, type Severity } from '../../core/finding.js';
import { calleeName, propName } from './ast.js';
import type { AstNode, SastRule } from './types.js';

export interface CustomRuleDef {
  id: string;
  severity: Severity;
  sources: string[];
  sinks: string[];
  message: string;
}

const ID = /^[A-Z][A-Z0-9-]{2,64}$/;
const TOKEN = /^[A-Za-z_][A-Za-z0-9_.]*$/;
const JS = /\b(?:function|eval|require|import|new\s+Function)\b|=>/;

let active: readonly SastRule[] = [];

export function setCustomRules(rules: readonly SastRule[] | undefined): void {
  active = rules ?? [];
}

export function activeCustomRules(): readonly SastRule[] {
  return active;
}

export function customRulesEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES === '1';
}

/** JSON only. JavaScript in a field is rejected and the rule is not run. */
export async function loadCustomRules(cwd: string, file: string): Promise<SastRule[]> {
  const path = isAbsolute(file) ? file : join(cwd, file);
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new ConfigError(`custom rules file cannot be read (${error instanceof Error ? error.message : String(error)})`);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError('custom rules file must be a JSON object');
  }
  const body = raw as Record<string, unknown>;
  const extra = Object.keys(body).filter((key) => key !== 'rules');
  if (extra.length > 0) throw new ConfigError(`custom rules file has unknown key "${extra[0]}"`);
  if (!Array.isArray(body.rules) || body.rules.length === 0) {
    throw new ConfigError('custom rules file "rules" must be a non-empty array');
  }
  return body.rules.map((row, index) => customRule(parseDef(row, index)));
}

function parseDef(row: unknown, index: number): CustomRuleDef {
  if (row === null || typeof row !== 'object' || Array.isArray(row)) {
    throw new ConfigError(`custom rules[${index}] must be an object`);
  }
  const rec = row as Record<string, unknown>;
  const allowed = new Set(['id', 'severity', 'sources', 'sinks', 'message']);
  for (const key of Object.keys(rec)) {
    if (!allowed.has(key)) throw new ConfigError(`custom rules[${index}] has unknown key "${key}"`);
  }
  const id = rec.id;
  const severity = rec.severity;
  const message = rec.message;
  if (typeof id !== 'string' || !ID.test(id)) throw new ConfigError(`custom rules[${index}].id is invalid`);
  if (typeof severity !== 'string' || !isSeverity(severity)) {
    throw new ConfigError(`custom rules[${index}].severity is invalid`);
  }
  if (typeof message !== 'string' || message.length === 0 || JS.test(message)) {
    throw new ConfigError(`custom rules[${index}].message is invalid`);
  }
  return {
    id,
    severity,
    sources: tokens(rec.sources, index, 'sources'),
    sinks: tokens(rec.sinks, index, 'sinks'),
    message,
  };
}

function tokens(value: unknown, index: number, field: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new ConfigError(`custom rules[${index}].${field} must be a non-empty array`);
  }
  return value.map((item) => {
    if (typeof item !== 'string' || !TOKEN.test(item) || JS.test(item)) {
      throw new ConfigError(`custom rules[${index}].${field} contains a value that is not a name`);
    }
    return item;
  });
}

function exprName(node: AstNode): string | undefined {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const prop = propName(node);
    const object = exprName(node.object);
    if (prop === undefined || object === undefined) return undefined;
    return `${object}.${prop}`;
  }
  return undefined;
}

export function customRule(def: CustomRuleDef): SastRule {
  const sources = new Set(def.sources);
  const sinks = new Set(def.sinks);
  return {
    meta: {
      id: def.id,
      title: def.message,
      severity: def.severity,
      cwe: 'CWE-0',
      docs: 'custom-rule',
    },
    create(ctx) {
      return {
        CallExpression(node) {
          if (node.type !== 'CallExpression') return;
          const name = calleeName(node);
          if (name === undefined || !sinks.has(name)) return;
          const hit = node.arguments.some((arg) => {
            const text = exprName(arg);
            return text !== undefined && sources.has(text);
          });
          if (!hit) return;
          ctx.report({ node, message: def.message });
        },
      };
    },
  };
}
