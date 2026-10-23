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

interface ScriptState {
  env: Map<string, string>;
  steps: ScriptStep[];
  effects: Set<ScriptResult['effects'][number]>;
  hosts: Set<string>;
  ruleIds: Set<string>;
  readsNpmrc: boolean;
  events: ScriptResult['events'];
  source: string;
}

function blankResult(): ScriptResult {
  return { ruleIds: [], steps: [], events: [], effects: [], hosts: [], readsNpmrc: false, executed: false };
}

function foldText(source: string): { text: string; events: ScriptResult['events'] } {
  const folded = process.env[DEOBFUSC_FLAG] === '1' ? foldSource(source) : { text: source, partial: false, events: [] as string[] };
  return { text: folded.text, events: folded.events.map((detail) => ({ code: 271 as const, detail })) };
}

function evalStopped(text: string, source: string, events: ScriptResult['events']): ScriptResult | undefined {
  if (!/\beval\s*\(/.test(text) && !/\bFunction\s*\(/.test(text)) {
    return undefined;
  }
  events.push({ code: 271, detail: 'eval stops the abstract branch' });
  const ruleIds = textualCurl(source) ? ['DEPS-SCRIPT-CURL-001'] : [];
  return { ruleIds, steps: [], events, effects: [], hosts: [], readsNpmrc: source.includes('.npmrc'), executed: false };
}

function keptLine(line: string): boolean {
  return line.length > 0 && !line.startsWith('/*') && !line.startsWith('*');
}

function statementLines(text: string): string[] {
  return text.split(/\n|;/).map((line) => stripLineComment(line).trim()).filter(keptLine);
}

function takeAssign(line: string, state: ScriptState): 'next' | 'stop' | 'miss' {
  const assign = /^(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/.exec(line);
  if (assign?.[1] === undefined || assign[2] === undefined) {
    return 'miss';
  }
  const value = evalConcat(assign[2], state.env, state.steps);
  if (value === undefined) {
    return 'stop';
  }
  state.env.set(assign[1], value);
  if (value.includes('.npmrc')) {
    state.readsNpmrc = true;
  }
  return 'next';
}

function takeEnv(line: string, state: ScriptState): boolean {
  const envRead = /process\.env\.([A-Za-z0-9_]+)/.exec(line);
  if (envRead === null || line.includes('(')) {
    return false;
  }
  state.effects.add('env');
  return true;
}

function noteNpmrc(callee: string, arg: string, state: ScriptState): void {
  if (callee === 'fs.readFileSync' && arg.includes('.npmrc')) {
    state.readsNpmrc = true;
  }
}

function outsideWrite(arg: string): boolean {
  return arg.startsWith('..') || arg.startsWith('/') || arg.startsWith('~/');
}

function noteWrite(callee: string, arg: string, state: ScriptState): void {
  if (callee !== 'fs.writeFileSync' && !callee.endsWith('.writeFileSync')) {
    return;
  }
  state.effects.add('fs-write');
  if (outsideWrite(arg)) {
    state.ruleIds.add('DEPS-SCRIPT-WRITE-001');
  }
}

function shellCallee(callee: string): boolean {
  return callee === 'exec' || callee === 'spawn' || callee.endsWith('.exec');
}

function noteShell(callee: string, arg: string, state: ScriptState): void {
  if (!shellCallee(callee)) {
    return;
  }
  state.effects.add('shell');
  state.steps.push({ op: 'exec', value: arg });
  if (textualCurl(arg)) {
    state.ruleIds.add('DEPS-SCRIPT-CURL-001');
  }
  for (const host of hostsIn(arg)) {
    state.hosts.add(host);
    state.effects.add('net');
  }
}

function noteNet(callee: string, arg: string, state: ScriptState): void {
  if (callee !== 'fetch' && callee !== 'http.get') {
    return;
  }
  state.effects.add('net');
  for (const host of hostsIn(arg)) {
    state.hosts.add(host);
  }
}

function takeCall(line: string, state: ScriptState): 'next' | 'stop' {
  const call = /^([A-Za-z0-9_.]+)\(([\s\S]*)\)$/.exec(line);
  if (call?.[1] === undefined || call[2] === undefined) {
    return 'stop';
  }
  const callee = call[1];
  const arg = evalConcat(call[2].split(',')[0] ?? '', state.env, state.steps) ?? '';
  noteNpmrc(callee, arg, state);
  noteWrite(callee, arg, state);
  noteShell(callee, arg, state);
  noteNet(callee, arg, state);
  return 'next';
}

function interpretLine(line: string, state: ScriptState): 'next' | 'stop' {
  const assigned = takeAssign(line, state);
  if (assigned !== 'miss') {
    return assigned;
  }
  if (takeEnv(line, state)) {
    return 'next';
  }
  return takeCall(line, state);
}

function burnFuel(state: ScriptState, fuel: number): number {
  const next = fuel - 1;
  if (next >= 0) {
    return next;
  }
  state.events.push({ code: 271, detail: 'script fuel exhausted' });
  if (textualCurl(state.source)) {
    state.ruleIds.add('DEPS-SCRIPT-CURL-001');
  }
  return next;
}

function runLines(text: string, state: ScriptState): void {
  let fuel = FUEL;
  for (const line of statementLines(text)) {
    fuel = burnFuel(state, fuel);
    if (fuel < 0 || interpretLine(line, state) === 'stop') {
      break;
    }
  }
}

function finish(state: ScriptState): ScriptResult {
  return {
    ruleIds: [...state.ruleIds],
    steps: state.steps,
    events: state.events,
    effects: [...state.effects],
    hosts: [...state.hosts],
    readsNpmrc: state.readsNpmrc,
    executed: false,
  };
}

export function interpretScript(source: string, path = 'scripts/install.js'): ScriptResult {
  if (!enabled() || path.split(/[/\\]/).includes('test')) {
    return blankResult();
  }
  const folded = foldText(source);
  const halted = evalStopped(folded.text, source, folded.events);
  if (halted !== undefined) {
    return halted;
  }
  const state: ScriptState = {
    env: new Map(),
    steps: [],
    effects: new Set(),
    hosts: new Set(),
    ruleIds: new Set(),
    readsNpmrc: false,
    events: folded.events,
    source,
  };
  runLines(folded.text, state);
  return finish(state);
}
