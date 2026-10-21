import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { makeFindingId, type Finding } from '../../../core/finding.js';
import { calleeName, propName } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

function loadModel(name: string): { entries?: unknown; libraries?: unknown } {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth += 1) {
    try {
      return JSON.parse(readFileSync(join(dir, 'models', name), 'utf8')) as { entries?: unknown };
    } catch {
      const parent = dirname(dir);
      if (parent === dir) {break;}
      dir = parent;
    }
  }
  return {};
}

interface SstiEntry {
  member: string;
  templateIndex: number;
}

function sstiEntries(): SstiEntry[] {
  const raw = loadModel('ssti.json').entries;
  if (!Array.isArray(raw)) {return [];}
  return raw.filter((row): row is SstiEntry => {
    if (typeof row !== 'object' || row === null) {return false;}
    const item = row as { member?: unknown; templateIndex?: unknown };
    return typeof item.member === 'string' && typeof item.templateIndex === 'number';
  });
}

interface WebhookEntry {
  id: string;
  body?: string;
  header?: string;
  verifiers: string[];
}

function webhookEntries(): WebhookEntry[] {
  const raw = loadModel('webhooks.json').entries;
  if (!Array.isArray(raw)) {return [];}
  return raw.flatMap((row) => {
    if (typeof row !== 'object' || row === null) {return [];}
    const item = row as { id?: unknown; body?: unknown; header?: unknown; verifiers?: unknown };
    if (typeof item.id !== 'string' || !Array.isArray(item.verifiers)) {return [];}
    return [{
      id: item.id,
      ...(typeof item.body === 'string' ? { body: item.body } : {}),
      ...(typeof item.header === 'string' ? { header: item.header } : {}),
      verifiers: item.verifiers.filter((name): name is string => typeof name === 'string'),
    }];
  });
}

function calleePath(node: AstNode): string | undefined {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {return undefined;}
  const name = calleeName(node);
  if (name === undefined) {return undefined;}
  if (node.callee.type === 'Identifier') {return name;}
  if (node.callee.type !== 'MemberExpression') {return name;}
  const object = node.callee.object;
  if (object.type === 'Identifier') {return `${object.name}.${name}`;}
  if (object.type === 'MemberExpression') {
    const outer = propName(object);
    return outer === undefined ? name : `${outer}.${name}`;
  }
  return name;
}

let passportVersion: string | undefined;
let packageBrowser = false;
let projectSources = new Map<string, string>();

export function setBreadthProject(input: { passportVersion?: string; packageBrowser?: boolean }): void {
  passportVersion = input.passportVersion;
  packageBrowser = input.packageBrowser === true;
}

export function setBreadthSources(sources: ReadonlyMap<string, string>): void {
  projectSources = new Map(sources);
}

export function clearBreadthProject(): void {
  passportVersion = undefined;
  packageBrowser = false;
  projectSources = new Map();
}

export function isBrowserSource(filename: string, source: string): boolean {
  if (/'use server'|"use server"/.test(source)) {return false;}
  if (/'use client'|"use client"/.test(source)) {return true;}
  if (/\bfrom\s+['"](?:react|vue|svelte)['"]|\brequire\(\s*['"](?:react|vue|svelte)['"]\s*\)/.test(source)) {return true;}
  if (/(^|\/)(app|pages|components)\//.test(filename.replace(/\\/g, '/'))) {return true;}
  return packageBrowser;
}

function secretSegment(name: string): boolean {
  if (name === 'tokenCount') {return false;}
  const lower = name.toLowerCase();
  const words = new Set(['password', 'passwd', 'secret', 'token', 'apikey', 'authorization']);
  if (words.has(lower)) {return true;}
  const parts = name.split(/[^A-Za-z0-9]+|(?=[A-Z])/).map((part) => part.toLowerCase()).filter((part) => part.length > 0);
  return parts.some((part) => words.has(part));
}

function authRoute(source: string): boolean {
  return /\/(login|signin|sign-in|auth|session)\b|function\s+\w*(login|auth)/i.test(source);
}

export const sstiRule: SastRule = {
  meta: {
    id: 'SAST-SSTI-001',
    title: 'Server-side template injection',
    severity: 'critical',
    cwe: 'CWE-1336',
    docs: 'https://cwe.mitre.org/data/definitions/1336.html',
  },
  create(ctx) {
    const entries = sstiEntries();
    return {
      'CallExpression'(node) {
        if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {return;}
        const path = calleePath(node);
        const entry = entries.find((row) => row.member === path || (path === 'Function' && row.member === 'Function'));
        if (entry === undefined) {return;}
        const arg = node.type === 'NewExpression' || node.type === 'CallExpression' ? node.arguments[entry.templateIndex] : undefined;
        if (arg === undefined || arg.type === 'SpreadElement' || arg.type === 'Literal') {return;}
        if (!ctx.isTainted(arg)) {return;}
        ctx.report({ node: arg, message: 'A tainted value is used as template source.' });
      },
      'NewExpression'(node) {
        if (node.type !== 'NewExpression') {return;}
        const path = calleePath(node);
        const entry = entries.find((row) => row.member === path);
        if (entry === undefined) {return;}
        const arg = node.arguments[entry.templateIndex];
        if (arg === undefined || arg.type === 'SpreadElement' || !ctx.isTainted(arg)) {return;}
        ctx.report({ node: arg, message: 'A tainted value is used as template source.' });
      },
    };
  },
};

export const logLeakRule: SastRule = {
  meta: {
    id: 'SAST-LOGLEAK-001',
    title: 'Secret written to a log',
    severity: 'medium',
    cwe: 'CWE-532',
    docs: 'https://cwe.mitre.org/data/definitions/532.html',
  },
  create(ctx) {
    const redacted = (text: string) =>
      /redact/.test(ctx.source) &&
      /pino|winston/.test(ctx.source) &&
      ((text.includes('authorization') && /redact[\s\S]{0,240}authorization/.test(ctx.source)) ||
        (text.includes('cookie') && /redact[\s\S]{0,240}cookie/.test(ctx.source)) ||
        (text.includes('body') && /redact[\s\S]{0,240}body/.test(ctx.source)));
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        const logged = name === 'log' || name === 'info' || name === 'warn' || name === 'error' || name === 'debug';
        if (!logged) {return;}
        for (const arg of node.arguments) {
          if (arg.type === 'SpreadElement') {continue;}
          const text = ctx.source.slice(arg.range?.[0] ?? 0, arg.range?.[1] ?? 0);
          if (redacted(text)) {continue;}
          if (/req\.headers\.(authorization|cookie)/.test(text)) {
            ctx.report({ node: arg, message: 'A request credential header is written to a log.' });
            return;
          }
          if (/req\.body\b/.test(text) && authRoute(ctx.source)) {
            ctx.report({ node: arg, message: 'A request body on an auth route is written to a log.' });
            return;
          }
          if (arg.type === 'Identifier' && secretSegment(arg.name)) {
            ctx.report({ node: arg, message: `Identifier ${arg.name} is written to a log.` });
            return;
          }
        }
      },
    };
  },
};

export const webhookRule: SastRule = {
  meta: {
    id: 'SAST-WEBHOOK-001',
    title: 'Webhook without a verifier',
    severity: 'high',
    cwe: 'CWE-345',
    docs: 'https://cwe.mitre.org/data/definitions/345.html',
  },
  create(ctx) {
    const entries = webhookEntries();
    let reported = false;
    return {
      CallExpression(node) {
        if (reported || node.type !== 'CallExpression') {return;}
        const matched = entries.filter((entry) => {
          if (entry.body !== undefined && ctx.source.includes(entry.body)) {return true;}
          if (entry.header !== undefined && ctx.source.includes(entry.header)) {return true;}
          return false;
        });
        if (matched.length === 0) {return;}
        const open = matched.find((entry) => !verifierCovers(entry, ctx.source));
        if (open === undefined) {return;}
        if (!/app\.(post|put|all)\s*\(/.test(ctx.source) && !/\.(post|put)\s*\(/.test(ctx.source)) {return;}
        reported = true;
        ctx.report({ node, message: `${open.id} webhook handler does not call a verifier.` });
      },
    };
  },
};

function verifierCovers(entry: WebhookEntry, handlerSource: string): boolean {
  if (entry.verifiers.some((name) => handlerSource.includes(name))) {return true;}
  const route = /['"](\/[^'"]+)['"]/.exec(handlerSource)?.[1];
  for (const source of projectSources.values()) {
    if (source === handlerSource) {continue;}
    if (!entry.verifiers.some((name) => source.includes(name))) {continue;}
    if (!/\.use\s*\(/.test(source)) {continue;}
    if (route !== undefined && source.includes(route)) {return true;}
    if (/app\.use\s*\(\s*[A-Za-z_$]/.test(source)) {return true;}
  }
  return false;
}

function semverGte(version: string, floor: string): boolean {
  const parse = (value: string) => value.split('.').map((part) => Number.parseInt(part, 10) || 0);
  const left = parse(version);
  const right = parse(floor);
  for (let i = 0; i < 3; i += 1) {
    if ((left[i] ?? 0) !== (right[i] ?? 0)) {return (left[i] ?? 0) > (right[i] ?? 0);}
  }
  return true;
}

export const sessionRule: SastRule = {
  meta: {
    id: 'SAST-SESSION-002',
    title: 'Session fixation on login',
    severity: 'medium',
    cwe: 'CWE-384',
    docs: 'https://cwe.mitre.org/data/definitions/384.html',
  },
  create(ctx) {
    return {
      AssignmentExpression(node) {
        if (node.type !== 'AssignmentExpression') {return;}
        const left = ctx.source.slice(node.left.range?.[0] ?? 0, node.left.range?.[1] ?? 0);
        if (!/req\.session\.(user|userId|uid|auth)/.test(left)) {return;}
        if (!authRoute(ctx.source)) {return;}
        const before = ctx.source.slice(0, node.range?.[0] ?? 0);
        if (before.includes('req.session.regenerate')) {return;}
        ctx.report({ node, message: 'Login writes the session without req.session.regenerate.' });
      },
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name !== 'login' && name !== 'logIn') {return;}
        const text = ctx.source.slice(node.callee.range?.[0] ?? 0, node.callee.range?.[1] ?? 0);
        if (!/req\.(login|logIn)/.test(text)) {return;}
        if (!authRoute(ctx.source)) {return;}
        if (passportVersion !== undefined && semverGte(passportVersion, '0.6.0')) {return;}
        const shown = passportVersion ?? 'unknown';
        ctx.report({
          node,
          message: `passport ${shown} is below 0.6.0, so req.login does not regenerate the session.`,
        });
      },
    };
  },
};

export const idorRule: SastRule = {
  meta: {
    id: 'SAST-IDOR-001',
    title: 'Handler loads by id without an ownership check',
    severity: 'low',
    cwe: 'CWE-639',
    docs: 'https://cwe.mitre.org/data/definitions/639.html',
  },
  create(ctx) {
    let reported = false;
    return {
      CallExpression(node) {
        if (reported || node.type !== 'CallExpression') {return;}
        if (!/:(id|userId)\b/.test(ctx.source)) {return;}
        if (/admin|role|permission|authorize/i.test(ctx.source)) {return;}
        const text = ctx.source.slice(node.range?.[0] ?? 0, node.range?.[1] ?? 0);
        if (/req\.user\b|req\.session\.user|ctx\.state\.user/.test(ctx.source)) {return;}
        const called = calleeName(node);
        const direct = /findById|findByPk|findUnique|WHERE id =/.test(text);
        if (!direct && (called === undefined || !helperLoadsById(called, ctx.filename))) {return;}
        reported = true;
        ctx.report({
          node,
          message: 'This handler loads a row by id and never references the authenticated user.',
          confidence: 'low',
          severity: 'low',
        });
      },
    };
  },
};

function helperLoadsById(name: string, file: string): boolean {
  for (const [other, source] of projectSources) {
    if (!new RegExp(`function\\s+${name}\\b`).test(source)) {continue;}
    if (!/findById|findByPk|findUnique|WHERE id =/.test(source)) {continue;}
    if (other !== file && /req\.user\b|req\.session\.user|ctx\.state\.user|admin|role|permission|authorize/i.test(source)) {return false;}
    if (other === file && /req\.user\b|req\.session\.user|ctx\.state\.user/.test(source)) {return false;}
    return true;
  }
  return false;
}

const BROWSER_SOURCE = /location\.(?:hash|search|href)|document\.(?:URL|referrer)|window\.name|event\.data|URLSearchParams\s*\(\s*location\./;

function boundBrowserNames(source: string): Set<string> {
  const names = new Set<string>();
  const re = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*(?:location\.(?:hash|search|href)|document\.(?:URL|referrer)|window\.name|new\s+URLSearchParams\s*\(\s*location\.)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(source)) !== null) {
    if (match[1] !== undefined) {names.add(match[1]);}
  }
  return names;
}

function browserTainted(text: string, names: ReadonlySet<string>): boolean {
  if (BROWSER_SOURCE.test(text)) {return true;}
  for (const name of names) {
    if (new RegExp(`\\b${name}\\b`).test(text)) {return true;}
  }
  return false;
}

export const domRule: SastRule = {
  meta: {
    id: 'SAST-DOMXSS-001',
    title: 'DOM XSS sink',
    severity: 'high',
    cwe: 'CWE-79',
    docs: 'https://cwe.mitre.org/data/definitions/79.html',
  },
  create(ctx) {
    if (!isBrowserSource(ctx.filename, ctx.source)) {return {};}
    const names = boundBrowserNames(ctx.source);
    return {
      AssignmentExpression(node) {
        if (node.type !== 'AssignmentExpression') {return;}
        const left = ctx.source.slice(node.left.range?.[0] ?? 0, node.left.range?.[1] ?? 0);
        const right = ctx.source.slice(node.right.range?.[0] ?? 0, node.right.range?.[1] ?? 0);
        const sink = /innerHTML|outerHTML|\.src|\.href/.test(left);
        if (!sink || !browserTainted(right, names)) {return;}
        if (/\.href|\.src/.test(left) && /https:/.test(ctx.source)) {return;}
        ctx.report({ node, message: 'A browser source is written to a DOM sink.' });
      },
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name !== 'write' && name !== 'insertAdjacentHTML' && name !== 'html' && name !== '$' && name !== 'eval' && name !== 'setTimeout' && name !== 'setInterval') {return;}
        const text = ctx.source.slice(node.range?.[0] ?? 0, node.range?.[1] ?? 0);
        if (!browserTainted(text, names)) {return;}
        ctx.report({ node, message: 'A browser source is passed to a DOM HTML sink.' });
      },
    };
  },
};

export const reactRule: SastRule = {
  meta: {
    id: 'SAST-REACT-001',
    title: 'Unsanitized HTML binding',
    severity: 'medium',
    cwe: 'CWE-79',
    docs: 'https://cwe.mitre.org/data/definitions/79.html',
  },
  create(ctx) {
    if (!isBrowserSource(ctx.filename, ctx.source)) {return {};}
    if (/DOMPurify|sanitize-html/.test(ctx.source)) {return {};}
    return {
      Program(node) {
        if (/v-html\s*=|\{@html/.test(ctx.source)) {
          ctx.report({ node, message: 'A template binds HTML without a sanitizer.' });
        }
      },
      Property(node) {
        if (node.type !== 'Property') {return;}
        const key = node.key.type === 'Identifier' ? node.key.name : '';
        if (key !== '__html') {return;}
        if (node.value.type === 'Literal') {return;}
        ctx.report({ node, message: 'dangerouslySetInnerHTML uses a non-literal value that is not passed through a sanitizer.' });
      },
    };
  },
};

export const postMessageRule: SastRule = {
  meta: {
    id: 'SAST-POSTMSG-001',
    title: 'postMessage without an origin check',
    severity: 'medium',
    cwe: 'CWE-346',
    docs: 'https://cwe.mitre.org/data/definitions/346.html',
  },
  create(ctx) {
    if (!isBrowserSource(ctx.filename, ctx.source)) {return {};}
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === 'addEventListener') {
          const event = node.arguments[0];
          const handler = node.arguments[1];
          if (event?.type !== 'Literal' || event.value !== 'message' || handler === undefined || handler.type === 'SpreadElement') {return;}
          const body = ctx.source.slice(handler.range?.[0] ?? 0, handler.range?.[1] ?? 0);
          if (!body.includes('event.data') || body.includes('event.origin')) {return;}
          ctx.report({ node, message: 'A message handler uses event.data and does not compare event.origin.' });
        }
        if (name === 'postMessage') {
          const target = node.arguments[1];
          if (target?.type === 'Literal' && target.value === '*') {
            const payload = node.arguments[0];
            const text = payload === undefined || payload.type === 'SpreadElement' ? '' : ctx.source.slice(payload.range?.[0] ?? 0, payload.range?.[1] ?? 0);
            if (/token|secret|jwt/i.test(text)) {
              ctx.report({ node, message: 'postMessage sends a secret-named value with target origin *.' });
            }
          }
        }
      },
    };
  },
};

export const tokenStoreRule: SastRule = {
  meta: {
    id: 'SAST-TOKENSTORE-001',
    title: 'Token written to localStorage',
    severity: 'low',
    cwe: 'CWE-922',
    docs: 'https://cwe.mitre.org/data/definitions/922.html',
  },
  create(ctx) {
    if (!isBrowserSource(ctx.filename, ctx.source)) {return {};}
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || calleeName(node) !== 'setItem') {return;}
        const object = node.callee.type === 'MemberExpression' ? node.callee.object : undefined;
        if (object?.type !== 'Identifier' || object.name !== 'localStorage') {return;}
        const key = node.arguments[0];
        const text = key === undefined || key.type === 'SpreadElement' ? '' : ctx.source.slice(key.range?.[0] ?? 0, key.range?.[1] ?? 0);
        if (!/token|jwt|accessToken/i.test(text)) {return;}
        ctx.report({ node, message: 'A token identifier is written to localStorage.', severity: 'low' });
      },
    };
  },
};

export const nextServerRule: SastRule = {
  meta: {
    id: 'SAST-NEXT-001',
    title: 'Server action writes without an auth check',
    severity: 'medium',
    cwe: 'CWE-306',
    docs: 'https://cwe.mitre.org/data/definitions/306.html',
  },
  create(ctx) {
    if (!/'use server'|"use server"/.test(ctx.source)) {return {};}
    const authed = /auth\s*\(|getServerSession|currentUser/.test(ctx.source) || (/cookies\s*\(/.test(ctx.source) && /verify/.test(ctx.source));
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === undefined) {return;}
        const direct = name === 'query' || name === 'execute' || name === 'update' || name === 'create' || name === 'delete';
        if (!direct && !helperWrites(name, ctx.filename)) {return;}
        if (authed) {return;}
        ctx.report({
          node,
          message: 'A use-server function writes through a data sink and does not call auth.',
          confidence: 'low',
          severity: 'medium',
        });
      },
    };
  },
};

function helperWrites(name: string, file: string): boolean {
  for (const [other, source] of projectSources) {
    if (!new RegExp(`function\\s+${name}\\b`).test(source)) {continue;}
    if (!/\b(?:query|execute|update|create|delete)\s*\(/.test(source)) {continue;}
    if (other !== file && /auth\s*\(|getServerSession|currentUser/.test(source)) {return false;}
    return true;
  }
  return false;
}

export function passportVersionFrom(lockText: string): string | undefined {
  const npm = /"node_modules\/passport"\s*:\s*\{[^}]*"version"\s*:\s*"([^"]+)"/.exec(lockText);
  if (npm?.[1] !== undefined) {return npm[1];}
  const yarn = /^"?passport@(\d+\.\d+\.\d+)/m.exec(lockText);
  return yarn?.[1];
}

export function scanBrowserMarkup(filename: string, source: string): Finding[] {
  if (!/\.(vue|svelte)$/.test(filename)) {return [];}
  if (/DOMPurify|sanitize-html/.test(source)) {return [];}
  if (!/v-html\s*=|\{@html/.test(source)) {return [];}
  return [{
    id: makeFindingId('SAST-REACT-001', filename, 'markup'),
    ruleId: 'SAST-REACT-001',
    module: 'sast',
    title: 'Unsanitized HTML binding',
    severity: 'medium',
    confidence: 'high',
    cwe: 'CWE-79',
    file: filename,
    line: 1,
    message: 'A template binds HTML without a sanitizer.',
    remediation: 'Unsanitized HTML binding. See https://cwe.mitre.org/data/definitions/79.html',
    references: ['https://cwe.mitre.org/data/definitions/79.html', 'CWE-79'],
  }];
}

export function nextProjectFindings(files: ReadonlyArray<{ file: string; source: string }>): Finding[] {
  const out: Finding[] = [];
  const middleware = files.find((entry) =>
    /(^|\/)middleware\.[cm]?[jt]s$/.test(entry.file) &&
    /matcher/.test(entry.source) &&
    /auth\s*\(|getServerSession|currentUser/.test(entry.source),
  );
  const bareHandler = files.some((entry) =>
    /(^|\/)(app|pages)\//.test(entry.file) &&
    !/(^|\/)middleware\.[cm]?[jt]s$/.test(entry.file) &&
    !/auth\s*\(|getServerSession|currentUser|cookies\s*\(/.test(entry.source),
  );
  if (middleware !== undefined && bareHandler) {
    out.push({
      id: makeFindingId('CONFIG-NEXT-001', middleware.file, 'middleware'),
      ruleId: 'CONFIG-NEXT-001',
      module: 'config',
      title: 'Auth enforced only in middleware',
      severity: 'info',
      confidence: 'low',
      file: middleware.file,
      line: 1,
      message: 'Auth is enforced only in middleware. The 2025 middleware-bypass class means the handler must enforce it too.',
      remediation: 'Enforce authentication in the route handler, not only in middleware.',
    });
  }
  for (const entry of files) {out.push(...scanNextText(entry.file, entry.source));}
  return out;
}

function scanNextText(filename: string, source: string): Finding[] {
  const out: Finding[] = [];
  const base = filename.split('/').pop() ?? filename;
  if (base === 'next.config.js' || base === 'next.config.mjs' || base === 'next.config.ts') {
    if (/remotePatterns[\s\S]{0,200}hostname\s*:\s*['"]\*\*['"]/.test(source) || /domains\s*:\s*\[[^\]]*['"]\*['"]/.test(source)) {
      out.push({
        id: makeFindingId('CONFIG-NEXT-002', filename, 'images'),
        ruleId: 'CONFIG-NEXT-002',
        module: 'config',
        title: 'Next.js image remote pattern is unrestricted',
        severity: 'medium',
        confidence: 'high',
        file: filename,
        line: 1,
        message: 'images.remotePatterns or images.domains allows every host.',
        remediation: 'List explicit image hostnames.',
      });
    }
  }
  const pub = source.match(/NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE|KEY)[A-Z0-9_]*/);
  if (pub?.[0] !== undefined && !pub[0].includes('PUBLISHABLE')) {
    out.push({
      id: makeFindingId('SECRET-NEXTPUB-001', filename, pub[0]),
      ruleId: 'SECRET-NEXTPUB-001',
      module: 'secrets',
      title: 'Public env name looks like a secret',
      severity: 'high',
      confidence: 'high',
      file: filename,
      line: 1,
      message: `${pub[0]} is exposed to the browser by the NEXT_PUBLIC_ prefix.`,
      remediation: 'Rename the variable so the secret is not shipped to the client.',
    });
  }
  return out;
}
