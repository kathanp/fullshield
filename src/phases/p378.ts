/**
 * Phase 378. Supply-chain policy file loader.
 * Off unless FULLSHIELD_EXPERIMENTAL_SCPOLICY=1.
 * Flag off: the file is not read. Unknown keys fail closed. No remote fetch.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SCPOLICY';
export const POLICY_FLAG = FLAG;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

const POLICY_KEYS = [
  'allowedRegistries',
  'allowedScriptCapabilities',
  'pinMode',
  'secretAllow',
  'privateRegistryHosts',
  'pinSeverity',
] as const;

export type PolicyKey = (typeof POLICY_KEYS)[number];

export interface SupplyChainPolicy {
  allowedRegistries: string[];
  allowedScriptCapabilities: string[];
  pinMode: 'exact' | 'range' | null;
  secretAllow: string[];
  privateRegistryHosts: string[];
  pinSeverity: 'info' | 'low' | 'medium' | null;
}

export interface PolicyLoad {
  policy: SupplyChainPolicy | null;
  /** True when the flag was off and the text was ignored. */
  ignored: boolean;
}

const PIN_MODES = new Set(['exact', 'range']);
const SEVERITIES = new Set(['info', 'low', 'medium']);

function stringList(value: unknown, key: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new FsError(`${key} must be an array of strings`);
  }
  return value as string[];
}

export function loadSupplyPolicy(text: string | null, location = 'fullshield.policy.json'): PolicyLoad {
  if (!enabled()) {
    return { policy: null, ignored: true };
  }
  if (location.startsWith('https://') || location.startsWith('http://')) {
    throw new FsError(`policy location is remote: ${location}`);
  }
  if (text === null) {
    return { policy: null, ignored: false };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new FsError('policy file is not JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new FsError('policy file must be an object');
  }
  const record = parsed as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!POLICY_KEYS.includes(key as PolicyKey)) {
      throw new FsError(`unknown policy key ${key}`);
    }
  }
  const policy: SupplyChainPolicy = {
    allowedRegistries: [],
    allowedScriptCapabilities: [],
    pinMode: null,
    secretAllow: [],
    privateRegistryHosts: [],
    pinSeverity: null,
  };
  if (record.allowedRegistries !== undefined) {
    policy.allowedRegistries = stringList(record.allowedRegistries, 'allowedRegistries');
  }
  if (record.allowedScriptCapabilities !== undefined) {
    policy.allowedScriptCapabilities = stringList(record.allowedScriptCapabilities, 'allowedScriptCapabilities');
  }
  if (record.secretAllow !== undefined) {
    policy.secretAllow = stringList(record.secretAllow, 'secretAllow');
  }
  if (record.privateRegistryHosts !== undefined) {
    policy.privateRegistryHosts = stringList(record.privateRegistryHosts, 'privateRegistryHosts');
  }
  if (record.pinMode !== undefined) {
    if (typeof record.pinMode !== 'string' || !PIN_MODES.has(record.pinMode)) {
      throw new FsError('pinMode is invalid');
    }
    policy.pinMode = record.pinMode as 'exact' | 'range';
  }
  if (record.pinSeverity !== undefined) {
    if (typeof record.pinSeverity !== 'string' || !SEVERITIES.has(record.pinSeverity)) {
      throw new FsError('pinSeverity rejects a non-string value');
    }
    policy.pinSeverity = record.pinSeverity as 'info' | 'low' | 'medium';
  }
  return { policy, ignored: false };
}
