import type { Finding } from '../../core/finding.js';
import { calleeName, walk } from './ast.js';
import { namedValueTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const MAIL_IMPORT = /(?:from|require\()\s*['"](?:nodemailer|@sendgrid\/mail|mailgun\.js)(?:\/[^'"]*)?['"]/;
const METHODS = new Set(['sendMail', 'send']);
const FIELDS = new Set(['to', 'cc', 'bcc', 'subject', 'from', 'replyTo', 'html', 'text']);

function mailCallTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name === undefined || !METHODS.has(name)) {return false;}
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    if (namedValueTainted(arg, facts, FIELDS)) {return true;}
  }
  return false;
}

function mailHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-MAIL-001',
    title: 'Mail header injection',
    cwe: 'CWE-93',
    message: 'Request data is copied into a mail header or body.',
    remediation: 'Pass a literal address and subject, or strip CR and LF from the field.',
    filename,
    source,
    node,
  });
}

export async function mailFindings(filename: string, source: string): Promise<Finding[]> {
  if (!MAIL_IMPORT.test(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (mailCallTainted(node, facts)) {findings.push(mailHit(filename, source, node));}
  });
  return findings;
}

export async function mailOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, mailFindings);
}
