import { join } from 'node:path';

import type { Finding } from '../../core/finding.js';

const SINK_RULES = new Set([
  'SAST-NOSQLI-001',
  'SAST-SQLI-001',
  'SAST-CMDI-001',
  'SAST-PATH-001',
  'SAST-SSRF-001',
  'SAST-XSS-001',
]);

const NON_SINK = new Set(['Array', 'ReadonlyArray', 'Map', 'Set', 'String', 'Number', 'Boolean']);

let missingNote: string | undefined;

export function typeReceiverNote(): string | undefined {
  return missingNote;
}

/**
 * Phase 80. Returns `types` when the receiver resolves to a non-sink type.
 * Unresolved and `any` keep the heuristic finding. Missing `typescript` does not change findings.
 */
export async function typeSuppressReason(
  cwd: string,
  files: readonly string[],
  finding: Finding,
): Promise<string | undefined> {
  if (!SINK_RULES.has(finding.ruleId) || finding.file === undefined || finding.line === undefined) return undefined;
  let ts: typeof import('typescript');
  try {
    ts = await import('typescript');
  } catch {
    missingNote = 'install typescript to use --experimental-types (FULLSHIELD_EXPERIMENTAL_TYPES)';
    return undefined;
  }
  const configPath = ts.findConfigFile(cwd, (path) => ts.sys.fileExists(path), 'tsconfig.json');
  const options = configPath
    ? ts.parseJsonConfigFileContent(
        ts.readConfigFile(configPath, (path) => ts.sys.readFile(path)).config,
        ts.sys,
        cwd,
      ).options
    : { allowJs: true, checkJs: false, noEmit: true, maxNodeModuleJsDepth: 0 };
  const rootNames = files.filter((file) => /\.[cm]?[jt]sx?$/.test(file)).map((file) => join(cwd, file));
  if (rootNames.length > 5000) return undefined;
  const program = ts.createProgram(rootNames, options);
  const source = program.getSourceFile(join(cwd, finding.file));
  if (source === undefined) return undefined;
  const checker = program.getTypeChecker();
  const line = finding.line;
  let reason: string | undefined;
  const visit = (node: import('typescript').Node): void => {
    if (reason !== undefined) return;
    if (ts.isCallExpression(node) && source.getLineAndCharacterOfPosition(node.getStart()).line + 1 === line) {
      const callee = node.expression;
      if (ts.isPropertyAccessExpression(callee)) {
        const type = checker.getTypeAtLocation(callee.expression);
        const name = checker.typeToString(type);
        if (name === 'any' || name === 'error') return;
        const symbol = type.getSymbol()?.getName() ?? name;
        if (NON_SINK.has(symbol) || name.startsWith('Array<') || name.endsWith('[]')) reason = 'types';
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return reason;
}
