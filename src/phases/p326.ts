/**
 * Phase 326. API keys in query strings.
 * Off unless FULLSHIELD_EXPERIMENTAL_APIKEYQUERY=1.
 * Header reads emit nothing. A name-only match that never reaches a compare is low.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_APIKEYQUERY';
export const RULE = 'SAST-APIKEY-QUERY-001';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const DEFAULT_APIKEY_NAMES = ['apiKey', 'api_key', 'api-key', 'accessToken', 'access_token'] as const;

export interface ApiKeyRead {
  file: string;
  line: number;
  from: 'query' | 'header' | 'url-search' | 'request-url';
  name: string;
  reachesCompare: boolean;
  authKind?: string;
  signedUrl?: boolean;
}

export interface ApiKeyConfig {
  names?: readonly string[];
  signedUrlNames?: readonly string[];
}

export interface ApiKeyFinding {
  ruleId: typeof RULE;
  severity: 'low' | 'medium';
  confidence: 'medium';
  file: string;
  line: number;
  message: string;
}

export function apiKeyFindings(reads: readonly ApiKeyRead[], config: ApiKeyConfig = {}): ApiKeyFinding[] {
  if (!enabled()) {
    return [];
  }
  const names = new Set<string>([...DEFAULT_APIKEY_NAMES, ...(config.names ?? [])]);
  const signed = new Set<string>(config.signedUrlNames ?? []);
  const findings: ApiKeyFinding[] = [];
  for (const read of reads) {
    const query = read.from === 'query' || read.from === 'url-search' || read.from === 'request-url';
    if (!query || read.signedUrl === true || signed.has(read.name)) {
      continue;
    }
    if (!names.has(read.name) && read.authKind !== 'apikey') {
      continue;
    }
    if (!read.reachesCompare) {
      findings.push({
        ruleId: RULE,
        severity: 'low',
        confidence: 'medium',
        file: read.file,
        line: read.line,
        message: `Query parameter ${read.name} matched an API key name. The match was by name.`,
      });
      continue;
    }
    findings.push({
      ruleId: RULE,
      severity: 'medium',
      confidence: 'medium',
      file: read.file,
      line: read.line,
      message: `API key ${read.name} is read from the query string.`,
    });
  }
  return findings;
}
