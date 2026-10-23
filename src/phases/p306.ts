import { parseProgram, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TEMPLATES';

export type TemplateEngine = 'ejs' | 'pug' | 'nunjucks' | 'handlebars' | 'marko';

export interface TemplateInput {
  engine: TemplateEngine;
  files: Readonly<Record<string, string>>;
  entry: string;
  taintedKeys: readonly string[];
}

export interface TemplateFinding {
  files: string[];
  raw: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeTemplates(input: TemplateInput): { findings: TemplateFinding[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], events: [] };}
  const events: UnsoundEvent[] = [];
  const findings: TemplateFinding[] = [];
  const helpers = safeHelpers(input.files);
  const seen = new Set<string>();
  const visit = (file: string, chain: string[]): void => {
    if (seen.has(file)) {return;}
    seen.add(file);
    const source = input.files[file];
    if (source === undefined) {return;}
    const parts = classify(input.engine, source);
    if (parts.unknown) {events.push({ kind: 'unknown-callee', file, line: 1, reason: 'unknown tag' });}
    for (const include of parts.includes) {
      const target = resolveInclude(include, input.files, file);
      if (target !== null) {visit(target, [...chain, file]);}
    }
    const rawHit = parts.raw.some((text) => mentions(text, input.taintedKeys) || helpers.some((helper) => text.includes(helper) && mentions(text, input.taintedKeys)));
    const helperHit = helpers.some((helper) => source.includes(`${helper} `) && mentions(source, input.taintedKeys));
    const unknownHit = parts.unknown && mentions(source, input.taintedKeys);
    if (rawHit || unknownHit || helperHit) {findings.push({ files: [...chain, file], raw: true });}
  };
  visit(input.entry, []);
  return { findings, events };
}

function classify(engine: TemplateEngine, source: string): { raw: string[]; includes: string[]; unknown: boolean } {
  if (engine === 'ejs') {return classifyEjs(source);}
  if (engine === 'handlebars') {return classifyHandlebars(source);}
  if (engine === 'nunjucks') {return classifyNunjucks(source);}
  if (engine === 'pug') {return classifyPug(source);}
  return classifyMarko(source);
}

function classifyEjs(source: string): { raw: string[]; includes: string[]; unknown: boolean } {
  const raw: string[] = [];
  const includes: string[] = [];
  let unknown = false;
  let index = 0;
  while (index < source.length) {
    const open = source.indexOf('<%', index);
    if (open < 0) {break;}
    const close = source.indexOf('%>', open);
    if (close < 0) {break;}
    const body = source.slice(open + 2, close);
    if (body.startsWith('-')) {raw.push(body.slice(1));}
    else if (body.startsWith(':') || body.startsWith('?')) {unknown = true; raw.push(body);}
    const include = /include\(['"]([^'"]+)['"]\)/.exec(body);
    if (include?.[1] !== undefined) {includes.push(include[1]);}
    index = close + 2;
  }
  return { raw, includes, unknown };
}

function classifyHandlebars(source: string): { raw: string[]; includes: string[]; unknown: boolean } {
  const raw: string[] = [];
  const includes: string[] = [];
  let unknown = false;
  let index = 0;
  while (index < source.length) {
    const open = source.indexOf('{{', index);
    if (open < 0) {break;}
    const triple = source.startsWith('{{{', open);
    const closeToken = triple ? '}}}' : '}}';
    const close = source.indexOf(closeToken, open + 2);
    if (close < 0) {break;}
    const body = source.slice(open + (triple ? 3 : 2), close).trim();
    if (triple || body.includes('SafeString')) {raw.push(body);}
    if (body.startsWith('>') || body.startsWith('include')) {
      const name = body.replace(/^[> ]*/, '').split(/\s+/)[0];
      if (name !== undefined) {includes.push(name);}
    }
    if (body.startsWith('unknown')) {unknown = true; raw.push(body);}
    index = close + closeToken.length;
  }
  return { raw, includes, unknown };
}

function classifyNunjucks(source: string): { raw: string[]; includes: string[]; unknown: boolean } {
  const raw: string[] = [];
  const includes: string[] = [];
  let unknown = false;
  let index = 0;
  while (index < source.length) {
    const open = source.indexOf('{{', index);
    const tag = source.indexOf('{%', index);
    const at = open < 0 ? tag : tag < 0 ? open : Math.min(open, tag);
    if (at < 0) {break;}
    if (at === tag) {
      const close = source.indexOf('%}', at);
      if (close < 0) {break;}
      const body = source.slice(at + 2, close);
      if (body.includes('include')) {
        const name = /['"]([^'"]+)['"]/.exec(body)?.[1];
        if (name !== undefined) {includes.push(name);}
      }
      if (body.includes('unknown')) {unknown = true; raw.push(body);}
      index = close + 2;
      continue;
    }
    const close = source.indexOf('}}', at);
    if (close < 0) {break;}
    const body = source.slice(at + 2, close);
    if (body.includes('| safe')) {raw.push(body);}
    index = close + 2;
  }
  return { raw, includes, unknown };
}

function classifyPug(source: string): { raw: string[]; includes: string[]; unknown: boolean } {
  const raw: string[] = [];
  const includes: string[] = [];
  let unknown = false;
  for (const line of source.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('!=') || trimmed.includes('!=')) {raw.push(trimmed);}
    if (trimmed.startsWith('include ')) {
      const name = trimmed.slice('include '.length).trim();
      includes.push(name);
    }
    if (trimmed.startsWith('unknown')) {unknown = true; raw.push(trimmed);}
  }
  return { raw, includes, unknown };
}

function classifyMarko(source: string): { raw: string[]; includes: string[]; unknown: boolean } {
  const raw: string[] = [];
  const includes: string[] = [];
  let unknown = false;
  let index = 0;
  while (index < source.length) {
    const rawAt = source.indexOf('$!{', index);
    const escAt = source.indexOf('${', index);
    const at = rawAt < 0 ? escAt : escAt < 0 ? rawAt : Math.min(rawAt, escAt);
    if (at < 0) {break;}
    const close = source.indexOf('}', at);
    if (close < 0) {break;}
    if (at === rawAt) {raw.push(source.slice(at + 3, close));}
    index = close + 1;
  }
  if (source.includes('<unknown')) {unknown = true; raw.push(source);}
  const include = /<include\(([^)]+)\)/.exec(source);
  if (include?.[1] !== undefined) {includes.push(include[1].replace(/['"]/g, ''));}
  return { raw, includes, unknown };
}

function mentions(text: string, keys: readonly string[]): boolean {
  return keys.some((key) => text.includes(key));
}

function resolveInclude(name: string, files: Readonly<Record<string, string>>, from: string): string | null {
  const candidates = [name, `${name}.ejs`, `${name}.pug`, `${name}.njk`, `${name}.hbs`, `${name}.marko`];
  for (const candidate of candidates) {
    if (files[candidate] !== undefined) {return candidate;}
  }
  const dir = from.split('/').slice(0, -1).join('/');
  for (const candidate of candidates) {
    const joined = dir.length === 0 ? candidate : `${dir}/${candidate}`;
    if (files[joined] !== undefined) {return joined;}
  }
  return null;
}

function safeHelpers(files: Readonly<Record<string, string>>): string[] {
  const names: string[] = [];
  for (const source of Object.values(files)) {
    if (!source.includes('SafeString')) {continue;}
    const program = parseProgram(source);
    if (program === null) {continue;}
    walkAst(program, (node) => {
      if (node.type === 'FunctionDeclaration' && node.id !== null && source.includes('SafeString')) {names.push(node.id.name);}
    });
  }
  return names;
}
