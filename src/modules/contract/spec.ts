import { normPath } from './path.js';

export const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']);

export interface SpecOp {
  method: string;
  path: string;
  line: number;
}

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) {line += 1;}
  }
  return line;
}

function isMethod(key: string): boolean {
  return HTTP_METHODS.has(key.toUpperCase());
}

function opsFromPaths(text: string, paths: unknown): SpecOp[] {
  if (paths === null || typeof paths !== 'object') {return [];}
  const ops: SpecOp[] = [];
  const entries = Object.entries(paths as Record<string, unknown>);
  for (const [path, item] of entries) {
    if (item === null || typeof item !== 'object') {continue;}
    const pathAt = text.indexOf(JSON.stringify(path));
    for (const key of Object.keys(item)) {
      if (!isMethod(key)) {continue;}
      const methodAt = pathAt < 0 ? -1 : text.indexOf(`"${key}"`, pathAt);
      ops.push({ method: key.toUpperCase(), path: normPath(path), line: lineAt(text, methodAt < 0 ? Math.max(pathAt, 0) : methodAt) });
    }
  }
  return ops;
}

function parseOpenApiJson(text: string): SpecOp[] | undefined {
  try {
    const doc = JSON.parse(text) as { paths?: unknown };
    if (doc === null || typeof doc !== 'object') {return [];}
    return opsFromPaths(text, doc.paths);
  } catch {
    return undefined;
  }
}

function yamlKey(line: string): { indent: number; key: string } | undefined {
  const match = /^( *)([^#\s][^:]*?):\s*(?:#.*)?$/.exec(line);
  if (match === null) {return undefined;}
  const key = (match[2] ?? '').trim().replace(/^['"]|['"]$/g, '');
  if (key === '') {return undefined;}
  return { indent: (match[1] ?? '').length, key };
}

function parseOpenApiYaml(text: string): SpecOp[] {
  const ops: SpecOp[] = [];
  let pathsIndent = -1;
  let pathIndent = -1;
  let opIndent = -1;
  let current = '';
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const parsed = yamlKey(lines[i] ?? '');
    if (parsed === undefined) {continue;}
    if (parsed.key === 'paths') {
      pathsIndent = parsed.indent;
      pathIndent = -1;
      current = '';
      continue;
    }
    if (pathsIndent < 0) {continue;}
    if (parsed.indent <= pathsIndent) {
      pathsIndent = -1;
      current = '';
      continue;
    }
    if (parsed.key.startsWith('/')) {
      current = normPath(parsed.key);
      pathIndent = parsed.indent;
      opIndent = -1;
      continue;
    }
    if (current === '' || parsed.indent <= pathIndent || !isMethod(parsed.key)) {continue;}
    if (opIndent === -1) {opIndent = parsed.indent;}
    if (parsed.indent === opIndent) {
      ops.push({ method: parsed.key.toUpperCase(), path: current, line: i + 1 });
    }
  }
  return ops;
}

export function parseSpec(file: string, source: string): SpecOp[] | undefined {
  const name = file.split('\\').join('/');
  if (name.endsWith('.json')) {return parseOpenApiJson(source);}
  if (name.endsWith('.yaml')) {return parseOpenApiYaml(source);}
  return undefined;
}
