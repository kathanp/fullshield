/**
 * Phase 400. WebSocket message cap.
 * Off unless FULLSHIELD_EXPERIMENTAL_WSGUARD=1.
 * Drops the message. Does not close the process and does not open a socket.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_WSGUARD';
export const DEFAULT_MAX_BYTES = 65536;
export const DEFAULT_MAX_DEPTH = 32;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface WsDecision {
  drop: boolean;
  delivered: boolean;
  event: boolean;
}

function jsonDepth(value: unknown, depth: number): number {
  if (typeof value !== 'object' || value === null) {
    return depth;
  }
  let max = depth;
  const entries = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  for (const entry of entries) {
    max = Math.max(max, jsonDepth(entry, depth + 1));
  }
  return max;
}

function configuredLimits(config?: { maxBytes?: number; maxDepth?: number }): { maxBytes: number; maxDepth: number } {
  return {
    maxBytes: config?.maxBytes ?? DEFAULT_MAX_BYTES,
    maxDepth: config?.maxDepth ?? DEFAULT_MAX_DEPTH,
  };
}

function schemaRejects(parsed: unknown, schema: Readonly<Record<string, string>> | undefined): boolean {
  if (schema === undefined || typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {return false;}
  const record = parsed as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (schema[key] === undefined) {return true;}
  }
  return false;
}

export function guardMessage(
  message: string,
  config?: { maxBytes?: number; maxDepth?: number; schema?: Readonly<Record<string, string>> },
): WsDecision {
  if (!enabled()) {
    return { drop: false, delivered: true, event: false };
  }
  const limits = configuredLimits(config);
  if (Buffer.byteLength(message) > limits.maxBytes) {
    return { drop: true, delivered: false, event: true };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(message) as unknown;
  } catch {
    return { drop: false, delivered: true, event: false };
  }
  if (jsonDepth(parsed, 0) > limits.maxDepth) {
    return { drop: true, delivered: false, event: true };
  }
  if (schemaRejects(parsed, config?.schema)) {
    return { drop: true, delivered: false, event: true };
  }
  return { drop: false, delivered: true, event: false };
}
