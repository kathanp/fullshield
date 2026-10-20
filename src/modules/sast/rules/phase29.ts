import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeName, literalString, propName, walk } from '../ast.js';
import { classesEnabled } from '../experimental.js';
import type { AstNode, RuleContext, SastRule } from '../types.js';

function gated(rule: SastRule): SastRule {
  return {
    meta: rule.meta,
    create(ctx) {
      if (!classesEnabled()) {return {};}
      return rule.create(ctx);
    },
  };
}

function objectProp(node: AstNode | undefined, name: string): AstNode | undefined {
  if (node === undefined || node.type !== 'ObjectExpression') {return undefined;}
  for (const prop of node.properties) {
    if (prop.type !== 'Property') {continue;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key === name) {return prop.value;}
  }
  return undefined;
}

function boolLiteral(node: AstNode | undefined): boolean | undefined {
  if (node === undefined || node.type !== 'Literal' || typeof node.value !== 'boolean') {return undefined;}
  return node.value;
}

function numberLiteral(node: AstNode | undefined): number | undefined {
  if (node === undefined || node.type !== 'Literal' || typeof node.value !== 'number') {return undefined;}
  return node.value;
}

function containsIdentMember(node: AstNode, objectName: string): boolean {
  let hit = false;
  walk(node, (child) => {
    if (child.type === 'MemberExpression' && child.object.type === 'Identifier' && child.object.name === objectName) {
      hit = true;
    }
  });
  return hit;
}

function containsCallNamed(node: AstNode, name: string): boolean {
  let hit = false;
  walk(node, (child) => {
    if (child.type === 'CallExpression' && calleeName(child) === name) {hit = true;}
  });
  return hit;
}

function containsOriginalName(node: AstNode): boolean {
  let hit = false;
  walk(node, (child) => {
    if (child.type === 'MemberExpression' && propName(child) === 'originalname') {hit = true;}
  });
  return hit;
}

function schemaLooksSafe(schema: AstNode | undefined): boolean {
  if (schema === undefined) {return false;}
  const name =
    schema.type === 'Identifier'
      ? schema.name
      : schema.type === 'MemberExpression'
        ? propName(schema)
        : undefined;
  return name !== undefined && /^(JSON_SCHEMA|CORE_SCHEMA|FAILSAFE_SCHEMA|SAFE_SCHEMA)$/.test(name);
}

type First = { kind: 'char'; c: string } | { kind: 'any' } | { kind: 'none' };

interface RedosFrag {
  nested: boolean;
  overlap: boolean;
  canRepeatInner: boolean;
  altOverlap: boolean;
  first: First;
}

function firstsOverlap(a: First, b: First): boolean {
  if (a.kind === 'none' || b.kind === 'none') {return false;}
  if (a.kind === 'any' || b.kind === 'any') {return true;}
  return a.c === b.c;
}

/** Static star-height / overlapping-quantifier check. Never compiles the pattern. */
export function patternHasRedos(pattern: string): boolean {
  if (pattern.length > 2000) {return false;}
  const st = { i: 0 };
  try {
    const frag = parseAlts(pattern, st);
    return frag.nested || frag.overlap;
  } catch {
    return false;
  }
}

function parseAlts(s: string, st: { i: number }): RedosFrag {
  const parts: RedosFrag[] = [parseSeq(s, st)];
  while (s[st.i] === '|') {
    st.i += 1;
    parts.push(parseSeq(s, st));
  }
  let altOverlap = false;
  for (let i = 0; i < parts.length; i += 1) {
    for (let j = i + 1; j < parts.length; j += 1) {
      if (firstsOverlap(parts[i]?.first ?? { kind: 'none' }, parts[j]?.first ?? { kind: 'none' })) {
        altOverlap = true;
      }
    }
  }
  return {
    nested: parts.some((p) => p.nested),
    overlap: parts.some((p) => p.overlap),
    canRepeatInner: parts.some((p) => p.canRepeatInner),
    altOverlap: altOverlap || parts.some((p) => p.altOverlap),
    first: parts[0]?.first ?? { kind: 'none' },
  };
}

function parseSeq(s: string, st: { i: number }): RedosFrag {
  const parts: RedosFrag[] = [];
  while (st.i < s.length && s[st.i] !== '|' && s[st.i] !== ')') {
    parts.push(parseAtom(s, st));
  }
  if (parts.length === 0) {
    return { nested: false, overlap: false, canRepeatInner: false, altOverlap: false, first: { kind: 'none' } };
  }
  return {
    nested: parts.some((p) => p.nested),
    overlap: parts.some((p) => p.overlap),
    canRepeatInner: parts.some((p) => p.canRepeatInner),
    altOverlap: false,
    first: parts.find((p) => p.first.kind !== 'none')?.first ?? { kind: 'none' },
  };
}

function parseAtom(s: string, st: { i: number }): RedosFrag {
  let frag: RedosFrag;
  const c = s[st.i];
  if (c === undefined) {
    return { nested: false, overlap: false, canRepeatInner: false, altOverlap: false, first: { kind: 'none' } };
  }
  if (c === '(') {
    st.i += 1;
    if (s.startsWith('?:', st.i) || s.startsWith('?=', st.i) || s.startsWith('?!', st.i)) {st.i += 2;}
    frag = parseAlts(s, st);
    if (s[st.i] === ')') {st.i += 1;}
  } else if (c === '[') {
    st.i += 1;
    if (s[st.i] === '^') {st.i += 1;}
    while (st.i < s.length && s[st.i] !== ']') {
      if (s[st.i] === '\\') {st.i += 2;}
      else {st.i += 1;}
    }
    if (s[st.i] === ']') {st.i += 1;}
    frag = { nested: false, overlap: false, canRepeatInner: false, altOverlap: false, first: { kind: 'any' } };
  } else if (c === '\\') {
    st.i += 1;
    const esc = s[st.i];
    st.i += 1;
    const any = esc !== undefined && /[dDwWsS]/.test(esc);
    frag = {
      nested: false,
      overlap: false,
      canRepeatInner: false,
      altOverlap: false,
      first: any ? { kind: 'any' } : { kind: 'char', c: esc ?? '' },
    };
  } else if (c === '.') {
    st.i += 1;
    frag = { nested: false, overlap: false, canRepeatInner: false, altOverlap: false, first: { kind: 'any' } };
  } else if (c === '^' || c === '$') {
    st.i += 1;
    frag = { nested: false, overlap: false, canRepeatInner: false, altOverlap: false, first: { kind: 'none' } };
  } else {
    st.i += 1;
    frag = { nested: false, overlap: false, canRepeatInner: false, altOverlap: false, first: { kind: 'char', c } };
  }
  const q = parseQuantifier(s, st);
  if (q === undefined) {return frag;}
  if (!q.repeating) {return frag;}
  return {
    nested: frag.nested || frag.canRepeatInner,
    overlap: frag.overlap || frag.altOverlap,
    canRepeatInner: true,
    altOverlap: false,
    first: frag.first,
  };
}

function parseQuantifier(s: string, st: { i: number }): { repeating: boolean } | undefined {
  const c = s[st.i];
  if (c === '*' || c === '+') {
    st.i += 1;
    if (s[st.i] === '?') {st.i += 1;}
    return { repeating: true };
  }
  if (c === '?') {
    st.i += 1;
    return { repeating: false };
  }
  if (c !== '{') {return undefined;}
  const rest = s.slice(st.i);
  const m = rest.match(/^\{(\d+)(,(\d+)?)?\}/);
  if (m === null) {return undefined;}
  st.i += m[0].length;
  if (s[st.i] === '?') {st.i += 1;}
  const min = Number(m[1]);
  const hasComma = m[2] !== undefined;
  const max = m[3] !== undefined ? Number(m[3]) : hasComma ? Number.POSITIVE_INFINITY : min;
  return { repeating: max > 1 };
}

function regexPatternOf(node: AstNode | undefined): string | undefined {
  if (node === undefined) {return undefined;}
  if (node.type === 'Literal' && 'regex' in node && node.regex !== null) {
    return node.regex.pattern;
  }
  if (
    (node.type === 'NewExpression' || node.type === 'CallExpression') &&
    node.callee.type === 'Identifier' &&
    node.callee.name === 'RegExp'
  ) {
    return literalString(node.arguments[0]);
  }
  return undefined;
}

function secretishName(name: string | undefined): boolean {
  if (name === undefined) {return false;}
  return /secret|token|password|passwd|pwd|hmac|signature|hash|apikey|api_key|credential/i.test(name);
}

function secretish(node: AstNode): boolean {
  if (node.type === 'Identifier') {return secretishName(node.name);}
  if (node.type === 'MemberExpression') {return secretishName(propName(node));}
  return false;
}

function isTimingSafeEqual(node: AstNode): boolean {
  return node.type === 'CallExpression' && calleeName(node) === 'timingSafeEqual';
}

function cookieFlagsComplete(opts: AstNode | undefined): boolean {
  if (opts === undefined || opts.type !== 'ObjectExpression') {return false;}
  const httpOnly = boolLiteral(objectProp(opts, 'httpOnly')) === true;
  const secure = boolLiteral(objectProp(opts, 'secure')) === true;
  const sameSite = objectProp(opts, 'sameSite');
  const hasSameSite =
    sameSite !== undefined &&
    ((sameSite.type === 'Literal' && typeof sameSite.value === 'string') || sameSite.type === 'Identifier');
  return httpOnly && secure && hasSameSite;
}

const PATH_CALLS = new Set([
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'createWriteStream',
  'rename',
  'copyFile',
  'join',
  'resolve',
  'sendFile',
  'open',
  'openSync',
]);

const redosRule: SastRule = {
  meta: {
    id: 'SAST-REDOS-001',
    title: 'Regular expression with nested or overlapping quantifiers on tainted input',
    severity: 'medium',
    cwe: 'CWE-1333',
    docs: 'https://cwe.mitre.org/data/definitions/1333.html',
  },
  create(ctx) {
    const redosNames = new Set<string>();
    return {
      VariableDeclarator(node) {
        if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier' || node.init === null) {return;}
        const pattern = regexPatternOf(node.init);
        if (pattern !== undefined && patternHasRedos(pattern)) {redosNames.add(node.id.name);}
      },
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === 'test' || name === 'exec') {
          const arg = node.arguments[0];
          if (arg === undefined || arg.type === 'SpreadElement' || !ctx.isTainted(arg)) {return;}
          if (node.callee.type !== 'MemberExpression') {return;}
          const pattern = regexPatternOf(node.callee.object);
          const named =
            node.callee.object.type === 'Identifier' && redosNames.has(node.callee.object.name);
          if ((pattern !== undefined && patternHasRedos(pattern)) || named) {
            ctx.report({ node, message: 'Tainted input is matched against a regex with nested or overlapping quantifiers.' });
          }
          return;
        }
        if (name === 'match' || name === 'search') {
          if (node.callee.type !== 'MemberExpression' || !ctx.isTainted(node.callee.object)) {return;}
          const arg = node.arguments[0];
          if (arg === undefined || arg.type === 'SpreadElement') {return;}
          const pattern = regexPatternOf(arg);
          if (pattern !== undefined && patternHasRedos(pattern)) {
            ctx.report({ node, message: 'Tainted input is matched against a regex with nested or overlapping quantifiers.' });
          }
        }
      },
    };
  },
};

const deserRule: SastRule = {
  meta: {
    id: 'SAST-DESER-001',
    title: 'Insecure deserialization of untrusted data',
    severity: 'high',
    cwe: 'CWE-502',
    docs: 'https://cwe.mitre.org/data/definitions/502.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        const arg0 = node.arguments[0];
        const taintedFirst = arg0 !== undefined && arg0.type !== 'SpreadElement' && ctx.isTainted(arg0);
        if (
          (name === 'unserialize' || name === 'deserialize' || name === 'deepDeserialize' || name === 'unsafeLoad') &&
          taintedFirst
        ) {
          ctx.report({ node, message: 'Tainted input is deserialized with an unsafe API (node-serialize, funcster, or yaml.unsafeLoad).' });
          return;
        }
        if (name === 'load' && taintedFirst) {
          const opts = node.arguments[1];
          const schema = opts !== undefined && opts.type !== 'SpreadElement' ? objectProp(opts, 'schema') : undefined;
          if (!schemaLooksSafe(schema)) {
            ctx.report({ node, message: 'js-yaml load() of tainted input uses an unsafe schema or default types.' });
          }
          return;
        }
        if (name === 'serialize') {
          const opts = node.arguments[1];
          const unsafe = opts !== undefined && opts.type !== 'SpreadElement' && boolLiteral(objectProp(opts, 'unsafe')) === true;
          if (unsafe) {
            ctx.report({ node, message: 'serialize-javascript is called with unsafe: true (eval path).' });
          }
          return;
        }
        if (name === 'eval' || name === 'runInNewContext') {
          const arg = node.arguments[0];
          if (arg !== undefined && arg.type !== 'SpreadElement' && containsCallNamed(arg, 'serialize')) {
            ctx.report({ node, message: 'serialize-javascript output is passed to eval / vm (insecure deserialize).' });
          }
        }
      },
    };
  },
};

const xxeRule: SastRule = {
  meta: {
    id: 'SAST-XXE-001',
    title: 'XML parser with external entities enabled on tainted input',
    severity: 'high',
    cwe: 'CWE-611',
    docs: 'https://cwe.mitre.org/data/definitions/611.html',
  },
  create(ctx) {
    const customEntities = /ENTITIES/.test(ctx.source);
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        const arg0 = node.arguments[0];
        const taintedFirst = arg0 !== undefined && arg0.type !== 'SpreadElement' && ctx.isTainted(arg0);
        if (!taintedFirst) {return;}
        if (name === 'parseXml' || name === 'parseXmlString') {
          const opts = node.arguments[1];
          if (opts !== undefined && opts.type !== 'SpreadElement' && boolLiteral(objectProp(opts, 'noent')) === true) {
            ctx.report({ node, message: 'libxmljs parses tainted XML with noent: true (external entities).' });
          }
          return;
        }
        if (name === 'parseString' || name === 'Parser') {
          const opts = node.arguments[1];
          const customOpt =
            opts !== undefined &&
            opts.type !== 'SpreadElement' &&
            (objectProp(opts, 'xmlns') !== undefined || objectProp(opts, 'entities') !== undefined);
          if (customEntities || customOpt) {
            ctx.report({ node, message: 'xml2js parses tainted XML with custom entity handling.' });
          }
        }
      },
    };
  },
};

const uploadRule: SastRule = {
  meta: {
    id: 'SAST-UPLOAD-001',
    title: 'Unrestricted file upload or originalname used as a path',
    severity: 'high',
    cwe: 'CWE-434',
    docs: 'https://cwe.mitre.org/data/definitions/434.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === 'multer' || name === 'busboy' || name === 'formidable' || name === 'IncomingForm') {
          const opts = node.arguments[0];
          const obj = opts !== undefined && opts.type !== 'SpreadElement' ? opts : undefined;
          const hasSize =
            objectProp(obj, 'limits') !== undefined ||
            objectProp(obj, 'maxFileSize') !== undefined ||
            objectProp(obj, 'fileSize') !== undefined;
          const hasType = objectProp(obj, 'fileFilter') !== undefined || objectProp(obj, 'filter') !== undefined;
          if (!hasSize || !hasType) {
            ctx.report({ node, message: `${name} is configured without a file size limit or type filter.` });
          }
          return;
        }
        if (name !== undefined && PATH_CALLS.has(name)) {
          const usesName = node.arguments.some(
            (arg) => arg.type !== 'SpreadElement' && containsOriginalName(arg),
          );
          if (usesName) {
            ctx.report({ node, message: 'Uploaded originalname is used in a filesystem path.' });
          }
        }
      },
      NewExpression(node) {
        if (node.type !== 'NewExpression') {return;}
        const name = calleeName(node);
        if (name !== 'IncomingForm' && name !== 'Formidable') {return;}
        const opts = node.arguments[0];
        const obj = opts !== undefined && opts.type !== 'SpreadElement' ? opts : undefined;
        if (objectProp(obj, 'maxFileSize') === undefined || objectProp(obj, 'filter') === undefined) {
          ctx.report({ node, message: `${name} is configured without a file size limit or type filter.` });
        }
      },
    };
  },
};

const CSRF_GUARD =
  /csrf-csrf|csrf-sync|csrfProtection|doubleCsrf|@fastify\/csrf-protection|\blusca\b|\bcsurf\b/;

/** True when this file loads a recognized CSRF library or middleware. */
export function sourceHasCsrfGuard(source: string): boolean {
  return CSRF_GUARD.test(source);
}

const cookieRule: SastRule = {
  meta: {
    id: 'SAST-COOKIE-001',
    title: 'Cookie missing httpOnly, secure, or sameSite',
    severity: 'medium',
    cwe: 'CWE-614',
    docs: 'https://cwe.mitre.org/data/definitions/614.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === 'cookie') {
          const opts = node.arguments[2];
          const optNode = opts !== undefined && opts.type !== 'SpreadElement' ? opts : undefined;
          if (!cookieFlagsComplete(optNode)) {
            ctx.report({ node, message: 'Cookie is set without httpOnly, secure, and sameSite.' });
          }
          return;
        }
        if (name === 'session') {
          const opts = node.arguments[0];
          const optNode = opts !== undefined && opts.type !== 'SpreadElement' ? opts : undefined;
          const secret = objectProp(optNode, 'secret');
          const cookie = objectProp(optNode, 'cookie');
          // A hardcoded session secret is SECRET-SESSION-001 only, so this rule does not add a second finding.
          if (literalString(secret) !== undefined) {return;}
          if (!cookieFlagsComplete(cookie)) {
            ctx.report({
              node,
              message: 'express-session cookie is missing httpOnly, secure, and sameSite.',
            });
          }
        }
      },
    };
  },
};

const csrfRule: SastRule = {
  meta: {
    id: 'SAST-CSRF-001',
    title: 'Cookie-authenticated state-changing route without CSRF protection',
    severity: 'high',
    cwe: 'CWE-352',
    docs: 'https://cwe.mitre.org/data/definitions/352.html',
  },
  create(ctx) {
    const cookieAuth = /express-session|cookie-session|cookieParser|req\.cookies|\.cookie\s*\(/.test(ctx.source);
    const csrfProtect = ctx.projectCsrfProtected === true || sourceHasCsrfGuard(ctx.source);
    const sameSiteOk = /sameSite\s*:\s*['"](strict|lax)['"]/.test(ctx.source);
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || !cookieAuth || csrfProtect || sameSiteOk) {return;}
        if (node.callee.type !== 'MemberExpression') {return;}
        const name = calleeName(node);
        if (name === undefined || !/^(post|put|patch|delete)$/.test(name)) {return;}
        const obj = node.callee.object;
        if (obj.type !== 'Identifier' || !/^(app|router)$/i.test(obj.name)) {return;}
        ctx.report({
          node,
          message: 'Cookie-authenticated POST/PUT/PATCH/DELETE has no CSRF protection and sameSite is not strict/lax.',
        });
      },
    };
  },
};

const massAssignRule: SastRule = {
  meta: {
    id: 'SAST-MASSASSIGN-001',
    title: 'Mass assignment of req.body without an allowlist or schema',
    severity: 'high',
    cwe: 'CWE-915',
    docs: 'https://cwe.mitre.org/data/definitions/915.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === 'assign') {
          const src = node.arguments[1];
          if (src !== undefined && src.type !== 'SpreadElement' && ctx.isRequestObject(src)) {
            ctx.report({ node, message: 'Object.assign copies req.body onto an object without an allowlist.' });
          }
          return;
        }
        if (name !== 'create' && name !== 'update' && name !== 'upsert') {return;}
        const body = node.arguments.find((arg) => arg.type !== 'SpreadElement' && ctx.isRequestObject(arg));
        if (body === undefined) {return;}
        const opts = node.arguments[1];
        if (
          opts !== undefined &&
          opts.type !== 'SpreadElement' &&
          (objectProp(opts, 'fields') !== undefined || objectProp(opts, 'whitelist') !== undefined)
        ) {
          return;
        }
        ctx.report({ node, message: `Model.${name}(req.body) assigns untrusted fields without an allowlist or schema.` });
      },
    };
  },
};

const timingRule: SastRule = {
  meta: {
    id: 'SAST-TIMING-001',
    title: 'Secret compared with === instead of timingSafeEqual',
    severity: 'medium',
    cwe: 'CWE-208',
    docs: 'https://cwe.mitre.org/data/definitions/208.html',
  },
  create(ctx) {
    return {
      BinaryExpression(node) {
        if (node.type !== 'BinaryExpression') {return;}
        if (node.operator !== '===' && node.operator !== '==') {return;}
        if (isTimingSafeEqual(node.left) || isTimingSafeEqual(node.right)) {return;}
        if (!secretish(node.left) && !secretish(node.right)) {return;}
        ctx.report({
          node,
          message: 'A secret/token/HMAC is compared with ===/== instead of crypto.timingSafeEqual.',
        });
      },
    };
  },
};

function argon2BelowOwasp(opts: AstNode | undefined): boolean {
  if (opts === undefined || opts.type !== 'ObjectExpression') {return false;}
  const memory = numberLiteral(objectProp(opts, 'memoryCost'));
  const time = numberLiteral(objectProp(opts, 'timeCost'));
  if (memory !== undefined && memory < 12288) {return true;}
  if (time !== undefined && time < 2) {return true;}
  if (memory !== undefined && time !== undefined && memory < 19456 && time < 3) {return true;}
  return false;
}

function pbkdf2BelowOwasp(iterations: number, digest: string | undefined): boolean {
  const algo = (digest ?? 'sha256').toLowerCase();
  if (algo === 'sha512') {return iterations < 210_000;}
  if (algo === 'sha1') {return iterations < 1_300_000;}
  return iterations < 600_000;
}

const hashRule: SastRule = {
  meta: {
    id: 'SAST-HASH-001',
    title: 'Password hash below OWASP minimum cost',
    severity: 'medium',
    cwe: 'CWE-916',
    docs: 'https://cwe.mitre.org/data/definitions/916.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === 'hash' || name === 'hashSync' || name === 'genSalt' || name === 'genSaltSync') {
          const costArg = name === 'genSalt' || name === 'genSaltSync' ? node.arguments[0] : node.arguments[1];
          const cost = numberLiteral(costArg);
          if (cost !== undefined && cost < 10) {
            ctx.report({ node, message: `bcrypt cost ${cost} is below the minimum of 10.` });
            return;
          }
          if (name === 'hash' || name === 'hashSync') {
            const opts = node.arguments[1];
            if (opts !== undefined && opts.type !== 'SpreadElement' && argon2BelowOwasp(opts)) {
              ctx.report({ node, message: 'argon2 options are below OWASP minimum memory/time cost.' });
            }
          }
          return;
        }
        if (name === 'pbkdf2' || name === 'pbkdf2Sync') {
          const iterations = numberLiteral(node.arguments[2]);
          const digest = literalString(node.arguments[4]);
          if (iterations !== undefined && pbkdf2BelowOwasp(iterations, digest)) {
            ctx.report({ node, message: `pbkdf2 iterations ${iterations} are below the OWASP minimum for ${digest ?? 'sha256'}.` });
          }
        }
      },
    };
  },
};

const GQL_SERVERS = new Set(['ApolloServer', 'GraphQLServer', 'YogaServer', 'graphqlHTTP']);

const gqlRule: SastRule = {
  meta: {
    id: 'SAST-GQL-001',
    title: 'GraphQL introspection, unbounded depth, or tainted resolver args',
    severity: 'medium',
    cwe: 'CWE-770',
    docs: 'https://cwe.mitre.org/data/definitions/770.html',
  },
  create(ctx) {
    const mentionsProduction = /NODE_ENV/.test(ctx.source) && /production/.test(ctx.source);
    return {
      NewExpression(node) {
        if (node.type !== 'NewExpression') {return;}
        const name = calleeName(node);
        if (name === undefined || !GQL_SERVERS.has(name)) {return;}
        reportGqlServer(ctx, node, node.arguments[0], mentionsProduction);
      },
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name !== undefined && GQL_SERVERS.has(name)) {
          reportGqlServer(ctx, node, node.arguments[0], mentionsProduction);
          return;
        }
        if (name !== 'query' && name !== 'execute' && name !== 'exec' && name !== 'eval') {return;}
        const sql = node.arguments[0];
        if (sql === undefined || sql.type === 'SpreadElement') {return;}
        if (!containsIdentMember(sql, 'args')) {return;}
        ctx.report({
          node,
          message: 'GraphQL resolver args reach a sink without validation (tainted resolver argument).',
        });
      },
    };
  },
};

function reportGqlServer(
  ctx: RuleContext,
  node: AstNode,
  optsArg: TSESTree.CallExpressionArgument | undefined,
  mentionsProduction: boolean,
): void {
  const opts = optsArg !== undefined && optsArg.type !== 'SpreadElement' ? optsArg : undefined;
  const introspection = objectProp(opts, 'introspection');
  const rules = objectProp(opts, 'validationRules');
  const hasDepth =
    (rules !== undefined && containsCallNamed(rules, 'depthLimit')) ||
    objectProp(opts, 'depthLimit') !== undefined ||
    /depthLimit|createComplexity|queryComplexity|costAnalysis/.test(ctx.source);
  const introOn = boolLiteral(introspection) === true;
  if (introOn && mentionsProduction) {
    ctx.report({ node, message: 'GraphQL introspection is enabled in production.' });
  }
  if (!hasDepth) {
    ctx.report({ node, message: 'GraphQL server has no depth or complexity limit.' });
  }
}

export const phase29Rules: readonly SastRule[] = [
  gated(redosRule),
  gated(deserRule),
  gated(xxeRule),
  gated(uploadRule),
  gated(cookieRule),
  gated(csrfRule),
  gated(massAssignRule),
  gated(timingRule),
  gated(hashRule),
  gated(gqlRule),
];
