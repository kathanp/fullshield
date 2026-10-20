import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { TypesConfig } from '../../core/config.js';
import { sortFindings, type Finding } from '../../core/finding.js';

/**
 * Receiver types Phase 80 treats as sinks. Phase 81 model packs are not loaded;
 * this table is the known set those packs name for SQL, NoSQL, command, path, SSRF, and XSS.
 * An empty type set means every type from that module is a sink.
 */
const SINK_TYPES: Readonly<Record<string, readonly string[]>> = {
  mongoose: ['Model', 'Query', 'Document', 'Aggregate'],
  mongodb: ['Collection', 'Db', 'MongoClient'],
  pg: ['Pool', 'PoolClient', 'Client'],
  mysql: ['Pool', 'PoolConnection', 'Connection', 'Query'],
  mysql2: ['Pool', 'PoolConnection', 'Connection', 'Query'],
  'better-sqlite3': ['Database'],
  sqlite3: ['Database'],
  knex: ['Knex'],
  sequelize: ['Sequelize', 'Model'],
  typeorm: ['DataSource', 'EntityManager', 'Repository', 'SelectQueryBuilder'],
  '@prisma/client': ['PrismaClient'],
  prisma: ['PrismaClient'],
  express: ['Response'],
  axios: ['Axios', 'AxiosInstance', 'AxiosStatic'],
  undici: ['Client', 'Pool'],
  got: ['Got'],
  execa: [],
  'node-fetch': [],
  needle: [],
  superagent: [],
  fs: [],
  'node:fs': [],
  'fs/promises': [],
  'node:fs/promises': [],
  child_process: [],
  'node:child_process': [],
  http: [],
  'node:http': [],
  https: [],
  'node:https': [],
};

const NON_SINK_GLOBALS = new Set([
  'Array',
  'ReadonlyArray',
  'Map',
  'ReadonlyMap',
  'WeakMap',
  'Set',
  'ReadonlySet',
  'WeakSet',
  'Promise',
  'Date',
  'RegExp',
  'String',
  'Number',
  'Boolean',
  'Object',
  'Function',
  'Error',
]);

const RECEIVER_RULES = new Set([
  'SAST-NOSQLI-001',
  'SAST-SQLI-001',
  'SAST-CMDI-001',
  'SAST-PATH-001',
  'SAST-SSRF-001',
  'SAST-XSS-001',
]);

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', '.git', 'coverage', '.next', 'out', '.fullshield']);

type TS = typeof import('typescript');
type Verdict = 'sink' | 'non-sink' | 'any';

/** Tests replace `load` to simulate a missing optional peer. */
export const typeScriptLoader = {
  load(): Promise<TS> {
    return import('typescript');
  },
};

const MISSING_TYPESCRIPT_NOTICE =
  'fullshield: FS-E012 optional peer typescript is not installed. Install with: npm i -D typescript';

export interface TypeSuppression {
  findings: Finding[];
  /** Present only when the checker ran. */
  suppressed?: Finding[];
  notice?: string;
}

function isMissingTypescript(error: unknown): boolean {
  const code = (error as { code?: string }).code;
  if (code === 'ERR_MODULE_NOT_FOUND' || code === 'MODULE_NOT_FOUND') return true;
  const message = error instanceof Error ? error.message : String(error);
  return /cannot find (package|module) ['"]typescript['"]/i.test(message);
}

function projectConfig(cwd: string): string | undefined {
  const tsconfig = join(cwd, 'tsconfig.json');
  if (existsSync(tsconfig)) return tsconfig;
  const jsconfig = join(cwd, 'jsconfig.json');
  if (existsSync(jsconfig)) return jsconfig;
  return undefined;
}

function listInferredFiles(cwd: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(abs);
      } else if (entry.isFile() && /\.[cm]?[jt]sx?$/.test(entry.name)) {
        out.push(abs);
      }
    }
  };
  walk(cwd);
  out.sort();
  return out;
}

function capNotice(count: number, maxFiles: number): string {
  return `fullshield: info type program has ${count} files, above types.maxFiles ${maxFiles}; using receiver heuristics`;
}

function ambientModuleName(ts: TS, node: import('typescript').Node | undefined): string | undefined {
  let current = node;
  while (current !== undefined) {
    if (ts.isModuleDeclaration(current) && ts.isStringLiteral(current.name)) return current.name.text;
    current = current.parent;
  }
  return undefined;
}

function packageFromFile(fileName: string): string | undefined {
  const file = fileName.replace(/\\/g, '/');
  const packed = file.match(/node_modules\/((?:@[^/]+\/)?[^/]+)\//);
  if (packed === null) return undefined;
  if (packed[1] === '@types/node') {
    const native = file.match(/\/(fs|child_process|http|https)(?:\/|$)/);
    if (native !== null) return native[1];
  }
  return packed[1];
}

function moduleOf(ts: TS, symbol: import('typescript').Symbol): string | undefined {
  for (const decl of symbol.declarations ?? []) {
    const named = ambientModuleName(ts, decl);
    if (named !== undefined) return named;
    const fromFile = packageFromFile(decl.getSourceFile().fileName);
    if (fromFile !== undefined) return fromFile;
  }
  return undefined;
}

function isSinkSymbol(ts: TS, checker: import('typescript').TypeChecker, symbol: import('typescript').Symbol | undefined): boolean {
  if (symbol === undefined) return false;
  let current = symbol;
  if ((current.flags & ts.SymbolFlags.Alias) !== 0) {
    current = checker.getAliasedSymbol(current);
  }
  const name = current.getName();
  const moduleName = moduleOf(ts, current);
  if (moduleName === undefined) return false;
  const names = SINK_TYPES[moduleName];
  if (names === undefined) return false;
  return names.length === 0 || names.includes(name);
}

function symbolsOf(type: import('typescript').Type): import('typescript').Symbol[] {
  const out: import('typescript').Symbol[] = [];
  if (type.aliasSymbol !== undefined) out.push(type.aliasSymbol);
  if (type.symbol !== undefined) out.push(type.symbol);
  const target = (type as { target?: import('typescript').Type }).target;
  if (target?.aliasSymbol !== undefined) out.push(target.aliasSymbol);
  if (target?.symbol !== undefined) out.push(target.symbol);
  return out;
}

function isAnyOrError(ts: TS, type: import('typescript').Type): boolean {
  const intrinsic = (type as { intrinsicName?: string }).intrinsicName;
  if (intrinsic === 'error' || intrinsic === 'any') return true;
  return (type.flags & ts.TypeFlags.Any) !== 0;
}

function classify(
  ts: TS,
  checker: import('typescript').TypeChecker,
  type: import('typescript').Type,
  seen: Set<import('typescript').Type>,
): Verdict {
  if (seen.has(type)) return 'non-sink';
  seen.add(type);
  if (isAnyOrError(ts, type)) return 'any';
  if ((type.flags & ts.TypeFlags.TypeParameter) !== 0) return 'any';
  if (type.isUnion() || type.isIntersection()) {
    const parts = type.types.filter(
      (part) => (part.flags & (ts.TypeFlags.Null | ts.TypeFlags.Undefined | ts.TypeFlags.Void)) === 0,
    );
    if (parts.length === 0) return 'any';
    let sink = false;
    let any = false;
    let nonSink = false;
    for (const part of parts) {
      const verdict = classify(ts, checker, part, seen);
      if (verdict === 'sink') sink = true;
      else if (verdict === 'any') any = true;
      else nonSink = true;
    }
    if (sink) return 'sink';
    if (any) return 'any';
    return nonSink ? 'non-sink' : 'any';
  }
  const primitive =
    ts.TypeFlags.String |
    ts.TypeFlags.Number |
    ts.TypeFlags.Boolean |
    ts.TypeFlags.BigInt |
    ts.TypeFlags.ESSymbol |
    ts.TypeFlags.StringLiteral |
    ts.TypeFlags.NumberLiteral |
    ts.TypeFlags.BooleanLiteral |
    ts.TypeFlags.Never;
  if ((type.flags & primitive) !== 0) return 'non-sink';

  for (const symbol of symbolsOf(type)) {
    if (isSinkSymbol(ts, checker, symbol)) return 'sink';
  }
  for (const symbol of symbolsOf(type)) {
    if (NON_SINK_GLOBALS.has(symbol.getName())) return 'non-sink';
  }
  const bases = type.getBaseTypes?.() ?? [];
  if (bases.length > 0) {
    let sink = false;
    let any = false;
    for (const base of bases) {
      const verdict = classify(ts, checker, base, seen);
      if (verdict === 'sink') sink = true;
      else if (verdict === 'any') any = true;
    }
    if (sink) return 'sink';
    if (any) return 'any';
  }
  if (symbolsOf(type).length > 0 || (type.flags & ts.TypeFlags.Object) !== 0) return 'non-sink';
  return 'any';
}

function unwrap(ts: TS, expr: import('typescript').Expression): import('typescript').Expression {
  let current = expr;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function receiverOf(ts: TS, call: import('typescript').CallExpression): import('typescript').Expression | undefined {
  const expr = unwrap(ts, call.expression);
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) return unwrap(ts, expr.expression);
  if (ts.isIdentifier(expr)) return expr;
  return undefined;
}

function callsOnLine(ts: TS, sourceFile: import('typescript').SourceFile, line: number): import('typescript').CallExpression[] {
  const found: import('typescript').CallExpression[] = [];
  const visit = (node: import('typescript').Node): void => {
    if (ts.isCallExpression(node)) {
      const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      if (pos.line + 1 === line) found.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

function sourceFileFor(program: import('typescript').Program, abs: string): import('typescript').SourceFile | undefined {
  const direct = program.getSourceFile(abs);
  if (direct !== undefined) return direct;
  const norm = abs.replace(/\\/g, '/');
  return program.getSourceFiles().find((file) => file.fileName.replace(/\\/g, '/') === norm);
}

function verdictFor(
  ts: TS,
  program: import('typescript').Program,
  checker: import('typescript').TypeChecker,
  cwd: string,
  finding: Finding,
): Verdict {
  if (finding.file === undefined || finding.line === undefined) return 'any';
  const sourceFile = sourceFileFor(program, resolve(cwd, finding.file));
  if (sourceFile === undefined) return 'any';
  const calls = callsOnLine(ts, sourceFile, finding.line);
  if (calls.length === 0) return 'any';
  const snippet = finding.snippet ?? '';
  const ranked = [...calls].sort((a, b) => {
    const score = (call: import('typescript').CallExpression): number => {
      const text = call.getText(sourceFile).replace(/\s+/g, ' ').trim().slice(0, 120);
      if (snippet.length > 0 && (text === snippet || snippet.startsWith(text) || text.startsWith(snippet))) return 0;
      if (finding.column !== undefined) {
        const pos = sourceFile.getLineAndCharacterOfPosition(call.getStart(sourceFile));
        if (pos.character === finding.column) return 1;
      }
      return 2;
    };
    return score(a) - score(b);
  });
  const call = ranked[0];
  if (call === undefined) return 'any';
  const receiver = receiverOf(ts, call);
  if (receiver === undefined) return 'any';
  return classify(ts, checker, checker.getTypeAtLocation(receiver), new Set());
}

function programRoots(ts: TS, cwd: string): { files: string[]; options: import('typescript').CompilerOptions } | { notice: string } {
  const configPath = projectConfig(cwd);
  if (configPath === undefined) {
    return {
      files: listInferredFiles(cwd),
      options: {
        allowJs: true,
        checkJs: false,
        noEmit: true,
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.CommonJS,
        moduleResolution: ts.ModuleResolutionKind.Node10,
        strict: false,
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        skipLibCheck: true,
      },
    };
  }
  const read = ts.readConfigFile(configPath, (path) => ts.sys.readFile(path));
  if (read.error !== undefined) {
    return { notice: `fullshield: info could not read ${configPath}; using receiver heuristics` };
  }
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, cwd, undefined, configPath);
  return {
    files: parsed.fileNames,
    options: { ...parsed.options, noEmit: true },
  };
}

/**
 * Move sink findings whose receiver type is a non-sink (Array, Map, user class)
 * into `suppressed`. Known sink types, `any`, and unresolved receivers stay.
 * This pass never adds a finding.
 */
export async function applyTypeSuppression(
  findings: readonly Finding[],
  cwd: string,
  types: TypesConfig,
): Promise<TypeSuppression> {
  let ts: TS;
  try {
    ts = await typeScriptLoader.load();
  } catch (error) {
    if (isMissingTypescript(error)) {
      return { findings: [...findings], notice: MISSING_TYPESCRIPT_NOTICE };
    }
    throw error;
  }

  const roots = programRoots(ts, cwd);
  if ('notice' in roots) return { findings: [...findings], notice: roots.notice };
  if (roots.files.length > types.maxFiles) {
    return { findings: [...findings], notice: capNotice(roots.files.length, types.maxFiles) };
  }

  const program = ts.createProgram(roots.files, roots.options);
  const checker = program.getTypeChecker();
  const kept: Finding[] = [];
  const dropped: Finding[] = [];
  for (const finding of findings) {
    if (!RECEIVER_RULES.has(finding.ruleId)) {
      kept.push(finding);
      continue;
    }
    const verdict = verdictFor(ts, program, checker, cwd, finding);
    if (verdict === 'non-sink') dropped.push({ ...finding, suppressedBy: 'types' });
    else kept.push(finding);
  }
  return { findings: sortFindings(kept), suppressed: sortFindings(dropped) };
}
