import { makeFindingId, type Finding } from '../../core/finding.js';
import { calleeName, isFunctionNode, walk } from './ast.js';
import { collectRequires, type ParsedSource } from './interproc.js';
import { nodeIsTainted } from './taint.js';
import { analyzeFile } from './taint.js';
import type { AstNode } from './types.js';

const SQL = new Set(['query', 'execute']);
const NOSQL = new Set(['find', 'findOne']);

interface ReturnedParam {
  file: string;
  name: string;
  params: string[];
  kind: 'sql' | 'nosql';
  line?: number;
}

/** Functions that return a SQL string or a Mongo filter built from a parameter. */
export function crossFileReturnFindings(parsed: readonly ParsedSource[]): Finding[] {
  const files = new Set(parsed.map((entry) => entry.file));
  const returned: ReturnedParam[] = [];
  for (const entry of parsed) {
    walk(entry.ast, (node) => {
      if (!isFunctionNode(node)) return;
      const name = functionName(node);
      if (name === undefined) return;
      const params = node.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : []));
      const ret = returnedExpression(node);
      if (ret === undefined) return;
      const kind = expressionKind(ret, new Set(params));
      if (kind === undefined) return;
      returned.push({ file: entry.file, name, params, kind, line: node.loc?.start.line });
    });
  }
  const byExport = new Map<string, ReturnedParam>();
  for (const row of returned) byExport.set(`${row.file}#${row.name}`, row);

  const findings: Finding[] = [];
  for (const entry of parsed) {
    const facts = analyzeFile(entry.ast);
    const imports = collectRequires(entry.file, entry.ast, files);
    walk(entry.ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const sink = calleeName(node);
      if (sink === undefined) return;
      const want = SQL.has(sink) ? 'sql' : NOSQL.has(sink) ? 'nosql' : undefined;
      if (want === undefined) return;
      for (const arg of node.arguments) {
        if (arg.type !== 'CallExpression' || arg.callee.type !== 'Identifier') continue;
        const spec = imports.get(arg.callee.name);
        if (spec === undefined || !spec.includes('#')) continue;
        const helper = byExport.get(spec);
        if (helper === undefined || helper.kind !== want) continue;
        const paramPos = helper.params.findIndex((name) => expressionMentions(returnedExpression(findFn(parsed, helper)), name));
        const passed = arg.arguments[Math.max(0, paramPos)];
        if (passed === undefined || passed.type === 'SpreadElement' || !nodeIsTainted(passed, facts)) continue;
        const ruleId = want === 'sql' ? 'SAST-SQLI-001' : 'SAST-NOSQLI-001';
        const snippet = entry.source.slice(node.range?.[0] ?? 0, node.range?.[1] ?? 0).replace(/\s+/g, ' ').trim().slice(0, 120);
        findings.push({
          id: makeFindingId(ruleId, entry.file, `${node.loc?.start.line ?? 0}|${snippet}`),
          ruleId,
          module: 'sast',
          title: want === 'sql' ? 'SQL injection' : 'NoSQL injection',
          severity: 'high',
          confidence: 'high',
          file: entry.file,
          line: node.loc?.start.line,
          snippet,
          message: `Value returned from ${helper.file} reaches ${sink}.`,
          remediation: 'Pass bound parameters. Do not build the query or filter from request input.',
          trace: [
            { file: helper.file, line: helper.line, note: `returned from ${helper.name}` },
            { file: entry.file, line: node.loc?.start.line, note: sink },
          ],
        });
      }
    });
  }
  return findings;
}

function findFn(parsed: readonly ParsedSource[], helper: ReturnedParam): AstNode | undefined {
  const entry = parsed.find((row) => row.file === helper.file);
  if (entry === undefined) return undefined;
  let found: AstNode | undefined;
  walk(entry.ast, (node) => {
    if (isFunctionNode(node) && functionName(node) === helper.name) found = node;
  });
  return found;
}

function functionName(node: AstNode): string | undefined {
  if (node.type === 'FunctionDeclaration' && node.id?.type === 'Identifier') return node.id.name;
  return undefined;
}

function returnedExpression(node: AstNode | undefined): AstNode | undefined {
  if (node === undefined || !isFunctionNode(node)) return undefined;
  let found: AstNode | undefined;
  walk(node.body, (child) => {
    if (child.type === 'ReturnStatement' && child.argument !== null && child.argument !== undefined) found = child.argument;
  });
  return found;
}

function expressionKind(node: AstNode, params: ReadonlySet<string>): 'sql' | 'nosql' | undefined {
  if (!mentionsAny(node, params)) return undefined;
  if (node.type === 'Literal' && typeof node.value === 'string') return undefined;
  let sql = false;
  let object = false;
  walk(node, (child) => {
    if (child.type === 'Literal' && typeof child.value === 'string' && /select|insert|update|delete/i.test(child.value)) sql = true;
    if (child.type === 'ObjectExpression') object = true;
  });
  if (node.type === 'BinaryExpression' || node.type === 'TemplateLiteral') {
    if (sql || textOf(node).includes('SELECT') || textOf(node).toLowerCase().includes('select')) return 'sql';
  }
  if (sql) return 'sql';
  if (object) return 'nosql';
  return undefined;
}

function textOf(node: AstNode): string {
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral') return node.quasis.map((q) => q.value.cooked ?? '').join('');
  if (node.type === 'BinaryExpression') return `${textOf(node.left)}${textOf(node.right)}`;
  return '';
}

function mentionsAny(node: AstNode, params: ReadonlySet<string>): boolean {
  let hit = false;
  walk(node, (child) => {
    if (child.type === 'Identifier' && params.has(child.name)) hit = true;
  });
  return hit;
}

function expressionMentions(node: AstNode | undefined, name: string): boolean {
  if (node === undefined) return false;
  return mentionsAny(node, new Set([name]));
}
