/**
 * Phase 353. Lifecycle-script abstract interpreter.
 * Off unless FULLSHIELD_EXPERIMENTAL_SCRIPTABS=1.
 * Interprets a statement subset. It does not call the script.
 */

import { foldSource } from './p354.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SCRIPTABS';
const DEOBFUSC_FLAG = 'FULLSHIELD_EXPERIMENTAL_DEOBFUSC';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ScriptStep {
  op: string;
  value: string;
}

export interface ScriptResult {
  ruleIds: string[];
  steps: ScriptStep[];
  events: { code: 271; detail: string }[];
  effects: ('net' | 'fs-write' | 'env' | 'shell')[];
  hosts: string[];
  readsNpmrc: boolean;
  executed: false;
}

const FUEL = 10_000;

function stripLineComment(line: string): string {
  let quote = '';
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index] ?? '';
    if (quote.length === 0 && char === '/' && line[index + 1] === '/') {
      return line.slice(0, index);
    }
    if (quote.length > 0 && char === '\\') {
      index += 1;
      continue;
    }
    if ((char === "'" || char === '"') && (quote.length === 0 || quote === char)) {
      quote = quote.length === 0 ? char : '';
    }
  }
  return line;
}

function stringLiteral(raw: string): string | undefined {
  const match = /^(['"])([\s\S]*)\1$/.exec(raw.trim());
  if (match?.[2] === undefined) {
    return undefined;
  }
  return match[2].replace(/\\x([0-9a-fA-F]{2})/g, (_all, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
}

function evalConcat(expr: string, env: Map<string, string>, steps: ScriptStep[]): string | undefined {
  const parts = expr.split('+').map((part) => part.trim());
  let acc = '';
  for (const part of parts) {
    const literal = stringLiteral(part);
    if (literal !== undefined) {
      acc += literal;
      continue;
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(part) || !env.has(part)) {
      return undefined;
    }
    acc += env.get(part) ?? '';
  }
  if (parts.length > 1) {
    steps.push({ op: 'concat', value: acc });
  }
  return acc;
}

function hostsIn(value: string): string[] {
  const hosts: string[] = [];
  for (const match of value.matchAll(/https?:\/\/([^/\s'")]+)/g)) {
    const host = match[1];
    if (host !== undefined) {
      hosts.push(host);
    }
  }
  return hosts;
}

function textualCurl(source: string): boolean {
  return /\bcurl\b/.test(source) || /\bwget\b/.test(source);
}

export function interpretScript(source: string, path = 'scripts/install.js'): ScriptResult {
  const empty: ScriptResult = { ruleIds: [], steps: [], events: [], effects: [], hosts: [], readsNpmrc: false, executed: false };
  if (!enabled()) {
    return empty;
  }
  if (path.split(/[/\\]/).includes('test')) {
    return empty;
  }
  const folded = process.env[DEOBFUSC_FLAG] === '1' ? foldSource(source) : { text: source, partial: false, events: [] };
  const events = folded.events.map((detail) => ({ code: 271 as const, detail }));
  const text = folded.text;
  if (/\beval\s*\(/.test(text) || /\bFunction\s*\(/.test(text)) {
    events.push({ code: 271, detail: 'eval stops the abstract branch' });
    const ruleIds = textualCurl(source) ? ['DEPS-SCRIPT-CURL-001'] : [];
    return { ruleIds, steps: [], events, effects: [], hosts: [], readsNpmrc: source.includes('.npmrc'), executed: false };
  }
  const env = new Map<string, string>();
  const steps: ScriptStep[] = [];
  const effects = new Set<ScriptResult['effects'][number]>();
  const hosts = new Set<string>();
  const ruleIds = new Set<string>();
  let readsNpmrc = false;
  let fuel = FUEL;
  const lines = text.split(/\n|;/).map((line) => stripLineComment(line).trim()).filter((line) => line.length > 0 && !line.startsWith('/*') && !line.startsWith('*'));
  for (const line of lines) {
    fuel -= 1;
    if (fuel < 0) {
      events.push({ code: 271, detail: 'script fuel exhausted' });
      if (textualCurl(source)) {
        ruleIds.add('DEPS-SCRIPT-CURL-001');
      }
      break;
    }
    const assign = /^(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/.exec(line);
    if (assign?.[1] !== undefined && assign[2] !== undefined) {
      const value = evalConcat(assign[2], env, steps);
      if (value === undefined) {
        break;
      }
      env.set(assign[1], value);
      if (value.includes('.npmrc')) {
        readsNpmrc = true;
      }
      continue;
    }
    const envRead = /process\.env\.([A-Za-z0-9_]+)/.exec(line);
    if (envRead !== null && !line.includes('(')) {
      effects.add('env');
      continue;
    }
    const call = /^([A-Za-z0-9_.]+)\(([\s\S]*)\)$/.exec(line);
    if (call?.[1] === undefined || call[2] === undefined) {
      break;
    }
    const callee = call[1];
    const arg = evalConcat(call[2].split(',')[0] ?? '', env, steps) ?? '';
    if (callee === 'fs.readFileSync' && arg.includes('.npmrc')) {
      readsNpmrc = true;
    }
    if (callee === 'fs.writeFileSync' || callee.endsWith('.writeFileSync')) {
      effects.add('fs-write');
      if (arg.startsWith('..') || arg.startsWith('/') || arg.startsWith('~/')) {
        ruleIds.add('DEPS-SCRIPT-WRITE-001');
      }
    }
    if (callee === 'exec' || callee === 'spawn' || callee.endsWith('.exec')) {
      effects.add('shell');
      steps.push({ op: 'exec', value: arg });
      if (/\bcurl\b/.test(arg) || /\bwget\b/.test(arg)) {
        ruleIds.add('DEPS-SCRIPT-CURL-001');
      }
      for (const host of hostsIn(arg)) {
        hosts.add(host);
        effects.add('net');
      }
    }
    if (callee === 'fetch' || callee === 'http.get') {
      effects.add('net');
      for (const host of hostsIn(arg)) {
        hosts.add(host);
      }
    }
    if (callee === 'console.log') {
      continue;
    }
  }
  return { ruleIds: [...ruleIds], steps, events, effects: [...effects], hosts: [...hosts], readsNpmrc, executed: false };
}
