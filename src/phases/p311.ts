/**
 * Phase 311. Authentication mechanism model.
 * Off unless FULLSHIELD_EXPERIMENTAL_AUTHMECH=1.
 * Flag off: the route list is returned unchanged and no predicate is stored.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_AUTHMECH';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type AuthKind =
  | 'none'
  | 'session'
  | 'jwt'
  | 'apikey'
  | `passport:${string}`
  | `framework:${string}`
  | 'unknown';

export interface AuthOptions {
  session?: boolean;
  algorithms?: readonly string[];
  apiKeyFrom?: 'header' | 'query';
}

export interface AuthPredicate {
  kind: AuthKind;
  options: AuthOptions;
  uniform: boolean;
  witnessPaths: string[];
  authenticated: boolean;
}

export interface GuardStep {
  name: string;
  order: number;
  shape: 'middleware' | 'render-form';
  strategy?: string;
  options?: AuthOptions;
}

export interface ReachPath {
  id: string;
  steps: readonly GuardStep[];
}

export interface RouteDraft {
  method: string;
  path: string;
  file: string;
  line: number;
  routeOrder: number;
  reaches: readonly ReachPath[];
}

export interface AnnotatedRoute extends RouteDraft {
  auth: AuthPredicate;
}

export interface AuthConfig {
  frameworkNames?: readonly string[];
}

interface PathClass {
  id: string;
  kind: AuthKind;
  options: AuthOptions;
}

const LOOKS_LIKE_AUTH = new Set(['authenticate', 'requireAuth', 'isAuthenticated', 'guard']);

function catalogKind(step: GuardStep, config: AuthConfig): AuthKind | undefined {
  if (config.frameworkNames?.includes(step.name) === true) {
    return `framework:custom:${step.name}`;
  }
  if (step.name === 'passport.authenticate' || step.name === 'passport') {
    return `passport:${step.strategy ?? 'local'}`;
  }
  if (step.name === 'express-jwt' || step.name === 'jwt' || step.name === 'jsonwebtoken') {
    return 'jwt';
  }
  if (step.name === 'express-session' || step.name === 'cookie-session' || step.name === 'session') {
    return 'session';
  }
  if (step.name === 'apiKey' || step.name === 'apikey') {
    return 'apikey';
  }
  if (step.name === 'getServerSession' || step.name === 'NextAuth' || step.name === 'next-auth') {
    return 'framework:next-auth';
  }
  if (step.name === 'UseGuards' || step.name === 'NestGuard') {
    return 'framework:nest';
  }
  if (step.name === 'fastify-auth' || step.name === 'fastifyAuth') {
    return 'framework:fastify';
  }
  if (LOOKS_LIKE_AUTH.has(step.name)) {
    return 'unknown';
  }
  return undefined;
}

function classifyPath(path: ReachPath, routeOrder: number, config: AuthConfig): PathClass {
  let found: PathClass | undefined;
  for (const step of path.steps) {
    if (step.shape === 'render-form' || step.order >= routeOrder) {
      continue;
    }
    const kind = catalogKind(step, config);
    if (kind === undefined) {
      continue;
    }
    found = { id: path.id, kind, options: step.options ?? {} };
  }
  return found ?? { id: path.id, kind: 'none', options: {} };
}

function combine(paths: readonly PathClass[]): AuthPredicate {
  if (paths.length === 0) {
    return { kind: 'none', options: {}, uniform: true, witnessPaths: [], authenticated: false };
  }
  const nonePaths = paths.filter((item) => item.kind === 'none');
  if (nonePaths.length > 0) {
    const mixed = nonePaths.length !== paths.length;
    return {
      kind: 'none',
      options: {},
      uniform: !mixed,
      witnessPaths: mixed ? nonePaths.map((item) => item.id) : [],
      authenticated: false,
    };
  }
  const unknownPaths = paths.filter((item) => item.kind === 'unknown');
  if (unknownPaths.length > 0) {
    return {
      kind: 'unknown',
      options: unknownPaths[0]?.options ?? {},
      uniform: unknownPaths.length === paths.length,
      witnessPaths: unknownPaths.map((item) => item.id),
      authenticated: false,
    };
  }
  const first = paths[0];
  if (first === undefined) {
    return { kind: 'none', options: {}, uniform: true, witnessPaths: [], authenticated: false };
  }
  const differ = paths.filter((item) => item.kind !== first.kind);
  return {
    kind: first.kind,
    options: first.options,
    uniform: differ.length === 0,
    witnessPaths: differ.map((item) => item.id),
    authenticated: differ.length === 0,
  };
}

export function predicateFor(route: RouteDraft, config: AuthConfig = {}): AuthPredicate {
  return combine(route.reaches.map((path) => classifyPath(path, route.routeOrder, config)));
}

export function annotateRoutes(
  routes: readonly RouteDraft[],
  config: AuthConfig = {},
): readonly RouteDraft[] | AnnotatedRoute[] {
  if (!enabled()) {
    return routes;
  }
  return routes.map((route) => ({ ...route, auth: predicateFor(route, config) }));
}
