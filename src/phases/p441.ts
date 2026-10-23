/**
 * Phase 441. Config JSON Schema.
 * Off unless FULLSHIELD_EXPERIMENTAL_CFGSCHEMA=1.
 * Flag off: --check errors with FS-E and does not validate.
 * Keys match the keys src/core/config.ts already reads. No new product keys.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CFGSCHEMA';
export const SCHEMA_PATH = 'docs/config.schema.json';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function scannerSchemaPath(): string {
  return SCHEMA_PATH;
}

export function runtimeSchemaPath(): string {
  return SCHEMA_PATH;
}

const stringArray = { type: 'array', items: { type: 'string' } };

const CONFIG_SCHEMA: Record<string, unknown> = {
  $schema: 'https://' + 'json-schema.org/draft/2020-12/schema',
  $id: SCHEMA_PATH,
  type: 'object',
  additionalProperties: false,
  properties: {
    modules: stringArray,
    failOn: { type: 'string' },
    ignore: stringArray,
    defaultExcludes: { type: 'boolean' },
    excludes: stringArray,
    baseline: { type: 'string' },
    notify: {
      type: 'object',
      additionalProperties: false,
      properties: { slackWebhookEnv: { type: 'string' } },
    },
    deps: {
      type: 'object',
      additionalProperties: false,
      properties: {
        offline: { type: 'boolean' },
        cacheDir: { type: 'string' },
        capabilityPolicy: {
          type: 'object',
          additionalProperties: false,
          properties: {
            deny: { type: 'object', additionalProperties: stringArray },
            warn: { type: 'object', additionalProperties: stringArray },
          },
        },
      },
    },
    ai: {
      type: 'object',
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        maxCostUsd: { type: 'number' },
        maxFindings: { type: 'number' },
      },
    },
    sast: {
      type: 'object',
      additionalProperties: false,
      properties: {
        maxFileBytes: { type: 'number' },
        sources: { type: 'array' },
        sanitizers: { type: 'array' },
      },
    },
    types: {
      type: 'object',
      additionalProperties: false,
      properties: { maxFiles: { type: 'number' } },
    },
    semgrepRules: { type: 'string' },
  },
};

export interface CheckResult {
  ok: boolean;
  exitCode: number;
  code?: 'FS-E';
  errors: string[];
}

function schemaProps(schema: Record<string, unknown>): Record<string, unknown> | null {
  const properties = schema.properties;
  if (typeof properties !== 'object' || properties === null || Array.isArray(properties)) {
    return null;
  }
  return properties as Record<string, unknown>;
}

function checkObject(value: unknown, schema: Record<string, unknown>, path: string, errors: string[]): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    errors.push(`${path} must be an object`);
    return;
  }
  const record = value as Record<string, unknown>;
  const properties = schemaProps(schema);
  if (properties === null) {
    return;
  }
  if (schema.additionalProperties === false) {
    for (const key of Object.keys(record)) {
      if (properties[key] === undefined) {
        errors.push(`${path}: unknown key "${key}"`);
      }
    }
  }
  for (const [key, child] of Object.entries(record)) {
    const childSchema = properties[key];
    if (typeof childSchema !== 'object' || childSchema === null) {
      continue;
    }
    const next = childSchema as Record<string, unknown>;
    if (next.type === 'object' && typeof child === 'object' && child !== null && !Array.isArray(child)) {
      checkObject(child, next, `${path}.${key}`, errors);
    }
  }
}

export function checkConfig(doc: unknown): CheckResult {
  if (!enabled()) {
    return { ok: false, exitCode: 1, code: 'FS-E', errors: [] };
  }
  const errors: string[] = [];
  checkObject(doc, CONFIG_SCHEMA, 'config', errors);
  return errors.length === 0 ? { ok: true, exitCode: 0, errors } : { ok: false, exitCode: 1, errors };
}

export function schemaPropertyNames(): string[] {
  const properties = schemaProps(CONFIG_SCHEMA);
  return properties === null ? [] : Object.keys(properties);
}
