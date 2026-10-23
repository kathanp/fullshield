/**
 * Phase 465. Process manager units.
 * Off unless FULLSHIELD_EXPERIMENTAL_UNITFILE=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Parses PM2 ecosystem files and systemd units. Does not start a service.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { INSPECT_RULE, scanCommand } from './p463.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_UNITFILE';
export const UNIT_ROOT = 'CONFIG-UNIT-ROOT-001';
export const UNIT_SECRET = 'CONFIG-UNIT-SECRET-001';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface UnitFile {
  path: string;
  text: string;
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet?: string;
}

function propertyName(node: TSESTree.Node): string | null {
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  return null;
}

function literal(node: TSESTree.Node): string | number | null {
  if (node.type === 'Literal' && (typeof node.value === 'string' || typeof node.value === 'number')) {
    return node.value;
  }
  return null;
}

function appsFrom(text: string): Array<Record<string, string | number>> {
  let ast: TSESTree.Program;
  try {
    ast = parse(text, { loc: false, range: false, jsx: false });
  } catch {
    return [];
  }
  const apps: Array<Record<string, string | number>> = [];
  const visitObject = (node: TSESTree.ObjectExpression): void => {
    const row: Record<string, string | number> = {};
    for (const prop of node.properties) {
      if (prop.type !== 'Property') {
        continue;
      }
      const key = propertyName(prop.key);
      const value = literal(prop.value);
      if (key !== null && value !== null) {
        row[key] = value;
      }
      if (key === 'env' && prop.value.type === 'ObjectExpression') {
        for (const envProp of prop.value.properties) {
          if (envProp.type !== 'Property') {
            continue;
          }
          const envKey = propertyName(envProp.key);
          const envValue = literal(envProp.value);
          if (envKey !== null && typeof envValue === 'string') {
            row[`env:${envKey}`] = envValue;
          }
        }
      }
    }
    if (Object.keys(row).length > 0) {
      apps.push(row);
    }
  };
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'ObjectExpression') {
      visitObject(node);
    }
    for (const child of Object.values(node as unknown as Record<string, unknown>)) {
      if (Array.isArray(child)) {
        for (const item of child) {
          if (typeof item === 'object' && item !== null && 'type' in item) {
            visit(item as TSESTree.Node);
          }
        }
      } else if (typeof child === 'object' && child !== null && 'type' in child) {
        visit(child as TSESTree.Node);
      }
    }
  };
  visit(ast);
  return apps;
}

function fromPm2(file: UnitFile): PhaseFinding[] {
  const findings: PhaseFinding[] = [];
  for (const app of appsFrom(file.text)) {
    if (app.uid === 0 || app.user === 'root' || app.User === 'root') {
      findings.push({ ruleId: UNIT_ROOT, severity: 'high', file: file.path, line: 1, message: `root unit ${file.path}` });
    }
    for (const [key, value] of Object.entries(app)) {
      if (key.startsWith('env:') && typeof value === 'string' && SECRET.test(value)) {
        findings.push({ ruleId: UNIT_SECRET, severity: 'high', file: file.path, line: 1, message: `Environment secret in ${file.path}`, snippet: '****' });
      }
    }
    const command = typeof app.node_args === 'string' ? `node ${app.node_args}` : '';
    if (command.length > 0) {
      findings.push(...scanCommand('start', command, file.path).filter((hit) => hit.ruleId === INSPECT_RULE));
    }
  }
  return findings;
}

function fromSystemd(file: UnitFile): PhaseFinding[] {
  const findings: PhaseFinding[] = [];
  for (const line of file.text.split(/\r?\n/)) {
    const user = /^User=(.*)$/.exec(line.trim())?.[1];
    if (user === 'root' || user === '0') {
      findings.push({ ruleId: UNIT_ROOT, severity: 'high', file: file.path, line: 1, message: `User=root in ${file.path}` });
    }
    const env = /^Environment=(.*)$/.exec(line.trim())?.[1];
    if (env !== undefined && SECRET.test(env)) {
      findings.push({ ruleId: UNIT_SECRET, severity: 'high', file: file.path, line: 1, message: `Environment secret in ${file.path}`, snippet: '****' });
    }
    const exec = /^ExecStart=(.*)$/.exec(line.trim())?.[1];
    if (exec !== undefined) {
      findings.push(...scanCommand('start', exec, file.path).filter((hit) => hit.ruleId === INSPECT_RULE));
    }
  }
  return findings;
}

export function scanUnits(files: readonly UnitFile[], baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  for (const file of files) {
    if (file.path.endsWith('.service') || file.text.includes('[Service]')) {
      findings.push(...fromSystemd(file));
    } else {
      findings.push(...fromPm2(file));
    }
  }
  return [...baseline, ...findings];
}
