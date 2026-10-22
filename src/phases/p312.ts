/**
 * Phase 312. Authorization check recognition.
 * Off unless FULLSHIELD_EXPERIMENTAL_AUTHZ=1.
 * A check counts only when it dominates the sink with a return-or-throw shape.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_AUTHZ';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type AuthzKind = 'none' | 'role' | 'permission' | 'policy' | 'ownership' | 'unknown';

export interface AuthzCheck {
  name: string;
  order: number;
  shape: 'return-or-throw' | 'other';
  catalog: boolean;
  computed: boolean;
}

export interface SinkCheck {
  id: string;
  sinkClass: string;
  sinkOrder: number;
  checks: readonly AuthzCheck[];
}

export interface AuthzPredicate {
  kind: AuthzKind;
  check?: string;
}

export interface AnnotatedSink extends SinkCheck {
  authz: AuthzPredicate;
}

export interface AuthzConfig {
  names?: Readonly<Record<string, AuthzKind>>;
}

function catalogKind(name: string): AuthzKind | undefined {
  if (name === 'hasRole') {
    return 'role';
  }
  if (name === 'can' || name === 'CASL' || name === 'Ability') {
    return 'permission';
  }
  if (name === 'authorize' || name === 'casbin' || name === 'enforcer') {
    return 'policy';
  }
  if (name === 'isOwner' || name === 'ownership') {
    return 'ownership';
  }
  return undefined;
}

function checkKind(check: AuthzCheck, config: AuthzConfig): AuthzKind | undefined {
  if (check.computed) {
    return 'unknown';
  }
  const configured = config.names?.[check.name];
  if (configured !== undefined) {
    return configured;
  }
  if (!check.catalog) {
    return undefined;
  }
  return catalogKind(check.name);
}

export function predicateForSink(sink: SinkCheck, config: AuthzConfig = {}): AuthzPredicate {
  let found: AuthzPredicate = { kind: 'none' };
  for (const check of sink.checks) {
    if (check.order >= sink.sinkOrder || check.shape !== 'return-or-throw') {
      continue;
    }
    const kind = checkKind(check, config);
    if (kind === undefined) {
      continue;
    }
    found = { kind, check: check.name };
  }
  return found;
}

export function annotateSinks(
  sinks: readonly SinkCheck[],
  config: AuthzConfig = {},
): readonly SinkCheck[] | AnnotatedSink[] {
  if (!enabled()) {
    return sinks;
  }
  return sinks.map((sink) => ({ ...sink, authz: predicateForSink(sink, config) }));
}
