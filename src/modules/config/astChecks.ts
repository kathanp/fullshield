import { calleeName, literalString, walk } from '../sast/ast.js';
import { classesEnabled } from '../sast/experimental.js';
import type { AstNode } from '../sast/types.js';
import { configFinding } from './finding.js';
import type { Finding } from '../../core/finding.js';

export const configAstRuleIds = [
  'CONFIG-HELMET-001',
  'CONFIG-BODYLIMIT-001',
  'CONFIG-CORS-001',
  'CONFIG-RATELIMIT-001',
  'CONFIG-ERRSTACK-001',
  'CONFIG-DIRLIST-001',
  'CONFIG-TRUSTPROXY-001',
] as const;

function lineAt(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (source[i] === '\n') line += 1;
  }
  return line;
}

function objectProp(
  node: AstNode,
  name: string,
): AstNode | undefined {
  if (node.type !== 'ObjectExpression') return undefined;
  for (const prop of node.properties) {
    if (prop.type !== 'Property') continue;
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key === name) return prop.value;
  }
  return undefined;
}

export async function runConfigAstChecks(file: string, source: string): Promise<Finding[]> {
  const { parse } = await import('@typescript-eslint/typescript-estree');
  const ast = parse(source, {
    loc: true,
    range: true,
    comment: false,
    jsx: true,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  }) as AstNode;

  const findings: Finding[] = [];
  let createsApp = false;
  let createsAppLine: number | undefined;
  let usesHelmet = false;

  walk(ast, (node) => {
    if (node.type === 'CallExpression') {
      const name = calleeName(node);
      if (name === 'helmet') usesHelmet = true;
      // `express()` constructs an app. `express.Router()` does not — helmet
      // belongs on the app, not on every file that imports the package.
      if (name === 'express' && node.callee.type === 'Identifier') {
        createsApp = true;
        createsAppLine = node.loc?.start.line;
      }

      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'express' &&
        name === 'json'
      ) {
        const opts = node.arguments[0];
        const hasLimit = opts !== undefined && opts.type !== 'SpreadElement' && objectProp(opts, 'limit') !== undefined;
        if (!hasLimit) {
          findings.push(
            configFinding(
              'CONFIG-BODYLIMIT-001',
              'express.json() has no size limit',
              'low',
              file,
              'app.use(express.json()) is registered without a size limit.',
              "Pass a limit, e.g. express.json({ limit: '100kb' }).",
              node.loc?.start.line,
            ),
          );
        }
      }

      if (name === 'serveIndex') {
        findings.push(
          configFinding(
            'CONFIG-DIRLIST-001',
            'Directory listing enabled',
            'medium',
            file,
            'serveIndex() exposes directory contents over HTTP.',
            'Remove serve-index or restrict it behind auth; do not list ftp/logs/keys.',
            node.loc?.start.line,
          ),
        );
      }

      if (name === 'cors') {
        const opts = node.arguments[0];
        if (opts !== undefined && opts.type === 'ObjectExpression') {
          const origin = objectProp(opts, 'origin');
          const credentials = objectProp(opts, 'credentials');
          const star = origin !== undefined && literalString(origin) === '*';
          const credsOn = credentials !== undefined && credentials.type === 'Literal' && credentials.value === true;
          if (star && credsOn) {
            findings.push(
              configFinding(
                'CONFIG-CORS-001',
                'Permissive CORS with credentials',
                'high',
                file,
                "cors({ origin: '*', credentials: true }) reflects any Origin with credentials.",
                'Set origin to an explicit allow-list; never combine * with credentials: true.',
                node.loc?.start.line,
              ),
            );
          }
        }
      }

      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        /^(app|router)$/.test(node.callee.object.name) &&
        name !== undefined &&
        /^(get|post|put|patch|delete)$/.test(name)
      ) {
        const path = literalString(node.arguments[0]) ?? '';
        if (/login|signin|signup|\/auth/i.test(path)) {
          const hasLimiter = node.arguments.some(
            (arg) => arg.type === 'Identifier' && /rate|limit|slow/i.test(arg.name),
          );
          if (!hasLimiter) {
            findings.push(
              configFinding(
                'CONFIG-RATELIMIT-001',
                'Auth route without a rate limiter',
                'medium',
                file,
                `Route ${path} looks like an auth endpoint and has no rate limiter.`,
                'Apply express-rate-limit (or similar) to login/auth routes.',
                node.loc?.start.line,
              ),
            );
          }
        }
      }
    }

    if (
      node.type === 'MemberExpression' &&
      node.object.type === 'Identifier' &&
      /^(err|error)$/i.test(node.object.name) &&
      (node.property.type === 'Identifier' && node.property.name === 'stack')
    ) {
      findings.push(
        configFinding(
          'CONFIG-ERRSTACK-001',
          'Error stack leaked to the client',
          'medium',
          file,
          'err.stack is sent in a response and can leak internals.',
          'Log the stack server-side and send a generic error body to the client.',
          node.loc?.start.line,
        ),
      );
    }
  });

  const commentedLines: number[] = [];
  if (!usesHelmet) {
    const commented =
      /^\s*\/\/\s*(?:(?:const|let|var)\s+helmet\b|app\.use\(\s*helmet\b|.*require\(\s*['"]helmet['"]\s*\))/gim;
    for (const match of source.matchAll(commented)) {
      const index = match.index ?? 0;
      const line = lineAt(source, index);
      commentedLines.push(line);
      findings.push(
        configFinding(
          'CONFIG-HELMET-001',
          'Express app does not use helmet',
          'medium',
          file,
          'helmet is commented out; security headers are not applied.',
          'Uncomment or add app.use(helmet()) to set standard security headers.',
          line,
        ),
      );
    }
  }

  if (createsApp && !usesHelmet) {
    findings.push(
      configFinding(
        'CONFIG-HELMET-001',
        'Express app does not use helmet',
        'medium',
        file,
        'An Express app is created but helmet() is never applied.',
        'Add app.use(helmet()) to set standard security headers.',
        // Keep a file-level finding when a comment already carries the line so
        // scoring treats that as line-attribution, not a new detection.
        commentedLines.length > 0 ? undefined : createsAppLine,
      ),
    );
  }

  if (classesEnabled()) {
    let trustProxyTrue = false;
    let ipRateLimit = false;
    let trustLine: number | undefined;
    walk(ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const name = calleeName(node);
      if (name === 'set' && literalString(node.arguments[0]) === 'trust proxy') {
        const value = node.arguments[1];
        if (value !== undefined && value.type === 'Literal' && value.value === true) {
          trustProxyTrue = true;
          trustLine = node.loc?.start.line;
        }
      }
      if (name === 'enable' && literalString(node.arguments[0]) === 'trust proxy') {
        trustProxyTrue = true;
        trustLine = node.loc?.start.line;
      }
      if (name === 'rateLimit' || name === 'slowDown') {
        const opts = node.arguments[0];
        const keyGen =
          opts !== undefined && opts.type !== 'SpreadElement' ? objectProp(opts, 'keyGenerator') : undefined;
        const keyedByIp =
          keyGen === undefined ||
          (keyGen.type !== 'SpreadElement' && /ip/i.test(source.slice(keyGen.range?.[0] ?? 0, keyGen.range?.[1] ?? 0)));
        if (keyedByIp) ipRateLimit = true;
      }
    });
    if (trustProxyTrue && ipRateLimit) {
      findings.push(
        configFinding(
          'CONFIG-TRUSTPROXY-001',
          'trust proxy true with IP-based rate limiting',
          'high',
          file,
          "app.set('trust proxy', true) makes X-Forwarded-For spoofable while rate limits key on IP.",
          'Set trust proxy to a hop count or subnet, and key rate limits on a verified identity—not the raw client IP.',
          trustLine,
        ),
      );
    }
  }

  return findings;
}
