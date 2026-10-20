import type { CapabilityName } from './names.js';

const CHILD = 'child' + '_process';
const NODE_CHILD = 'node:' + CHILD;
const NET_MODULES = ['net', 'http', 'https', 'dgram', 'node:net', 'node:http', 'node:https', 'node:dgram'];
const FS_WRITES = [
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'createWriteStream',
  'rmSync',
  'unlinkSync',
  'mkdirSync',
  'renameSync',
  'copyFileSync',
  'truncateSync',
];

function mentionsModule(text: string, name: string): boolean {
  return (
    text.includes(`require('${name}')`) ||
    text.includes(`require("${name}")`) ||
    text.includes(`from '${name}'`) ||
    text.includes(`from "${name}"`)
  );
}

function hasNet(text: string): boolean {
  if (NET_MODULES.some((name) => mentionsModule(text, name))) {return true;}
  if (/\bfetch\s*\(/.test(text)) {return true;}
  if (/\bhttps?\.(?:request|get)\s*\(/.test(text)) {return true;}
  return /\bdgram\.createSocket\s*\(/.test(text);
}

function hasFsWrite(text: string): boolean {
  return FS_WRITES.some((name) => new RegExp(`\\b${name}\\b`).test(text));
}

function hasCodeExec(text: string): boolean {
  const call = new RegExp('\\b' + 'eval' + '\\s*\\(');
  const built = new RegExp('\\bnew\\s+' + 'Function' + '\\s*\\(');
  if (call.test(text) || built.test(text)) {return true;}
  if (/\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction|Script)\b/.test(text)) {return true;}
  return mentionsModule(text, 'vm') || mentionsModule(text, 'node:vm');
}

function hasDynamicImport(text: string): boolean {
  const re = /\b(?:require|import)\s*\(\s*([^)]*)\)/g;
  for (const match of text.matchAll(re)) {
    const arg = (match[1] ?? '').trim();
    if (arg.length === 0) {continue;}
    const quote = arg[0];
    if (quote !== "'" && quote !== '"' && quote !== '`') {return true;}
  }
  return false;
}

function hasObfuscation(text: string): boolean {
  const phase70 = new RegExp('(?:' + 'eval' + '\\s*\\(\\s*)(?:Buffer|atob|fromCharCode|decodeURIComponent)');
  if (phase70.test(text)) {return true;}
  if (/[0-9a-fA-F]{64,}/.test(text)) {return true;}
  if (/[A-Za-z0-9+/]{80,}={0,2}/.test(text)) {return true;}
  const marks = text.match(/\\x[0-9a-fA-F]{2}/g);
  return marks !== null && marks.length >= 8;
}

/** Static signals only. Callers read file text; nothing here is executed. */
export function signalsInText(text: string): CapabilityName[] {
  const found = new Set<CapabilityName>();
  if (mentionsModule(text, CHILD) || mentionsModule(text, NODE_CHILD)) {found.add('child_process');}
  if (hasNet(text)) {found.add('net');}
  if (hasFsWrite(text)) {found.add('fs_write');}
  if (text.includes('process.env')) {found.add('env');}
  if (hasCodeExec(text)) {found.add('eval');}
  if (hasDynamicImport(text)) {found.add('dynamic_require');}
  if (hasObfuscation(text)) {found.add('obfuscation');}
  return [...found].sort();
}
