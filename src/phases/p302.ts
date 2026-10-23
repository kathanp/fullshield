import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_QUEUE';

export interface QueueFinding {
  file: string;
  line: number;
  origins: ('request' | 'queue')[];
  confidence: 'medium' | 'high';
  queue: string;
}

interface Producer {
  queue: string;
  request: boolean;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeQueue(source: string, options?: { file?: string }): { findings: QueueFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const producers: Producer[] = [];
  const findings: QueueFinding[] = [];
  walkAst(program, (node) => {
    if (node.type !== 'CallExpression') {return;}
    const callee = stripNode(node.callee);
    if (callee.type !== 'MemberExpression') {return;}
    const name = propName(callee);
    if (name === 'add' || name === 'send' || name === 'publish') {
      const queue = node.arguments[0];
      const payload = node.arguments[1];
      if (queue !== undefined && queue.type === 'Literal' && typeof queue.value === 'string' && payload !== undefined && payload.type !== 'SpreadElement') {
        producers.push({ queue: queue.value, request: isRequest(payload) });
      }
    }
  });
  walkAst(program, (node) => {noteProcess(node, producers, file, findings);});
  return { findings };
}

function noteProcess(node: TSESTree.Node, producers: readonly Producer[], file: string, findings: QueueFinding[]): void {
  const job = processJob(node);
  if (job === null) {return;}
  if (!reachesExec(job.handler, job.name) || parameterized(job.handler, job.name)) {return;}
  const linked = producers.some((producer) => producer.queue === job.queue && producer.request);
  findings.push({
    file,
    line: lineOf(node),
    origins: linked ? ['request', 'queue'] : ['queue'],
    confidence: linked ? 'high' : 'medium',
    queue: job.queue,
  });
}

function processJob(node: TSESTree.Node): { handler: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression; name: string; queue: string } | null {
  if (node.type !== 'CallExpression') {return null;}
  const callee = stripNode(node.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'process') {return null;}
  const queue = node.arguments[0];
  const handler = node.arguments[1];
  if (queue === undefined || queue.type !== 'Literal' || typeof queue.value !== 'string') {return null;}
  if (!isFn(handler)) {return null;}
  const param = handler.params[0];
  if (param === undefined || param.type !== 'Identifier') {return null;}
  return { handler, name: param.name, queue: queue.value };
}

function isFn(node: TSESTree.Node | undefined): node is TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression {
  return node !== undefined && (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression');
}

function isRequest(node: TSESTree.Node): boolean {
  if (isRequestSource(node)) {return true;}
  if (node.type === 'MemberExpression') {return isRequest(node.object);}
  return false;
}

function reachesExec(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression, job: string): boolean {
  let found = false;
  walkAst(fn, (node) => {
    if (node.type === 'CallExpression' && (node.callee.type === 'Identifier' && (node.callee.name === 'exec' || node.callee.name === 'execSync'))) {
      const arg = node.arguments[0];
      if (arg !== undefined && usesJob(arg, job)) {found = true;}
    }
  });
  return found;
}

function parameterized(fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression, job: string): boolean {
  let query = false;
  walkAst(fn, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression' || propName(node.callee) !== 'query') {return;}
    const sql = node.arguments[0];
    if (node.arguments.length >= 2 && sql !== undefined && sql.type === 'Literal' && typeof sql.value === 'string' && sql.value.includes('?') && node.arguments.some((arg) => arg.type !== 'SpreadElement' && usesJob(arg, job))) {
      query = true;
    }
  });
  return query && !reachesExec(fn, job);
}

function usesJob(node: TSESTree.Node, job: string): boolean {
  if (node.type === 'Identifier') {return node.name === job;}
  if (node.type === 'MemberExpression') {return usesJob(node.object, job);}
  if (node.type === 'ArrayExpression') {return node.elements.some((item) => item !== null && item.type !== 'SpreadElement' && usesJob(item, job));}
  if (node.type === 'BinaryExpression') {return usesJob(node.left, job) || usesJob(node.right, job);}
  return false;
}
