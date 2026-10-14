export type SinkKind = 'sql' | 'shell' | 'path' | 'nosql' | 'ssrf' | 'proto';

export interface RaspRequestContext {
  path: string;
  ip: string;
  strings: string[];
  objects: unknown[];
}

export interface Decision {
  block: boolean;
  ruleId?: string;
}

export interface RaspEvent {
  ruleId: string;
  path: string;
  ip: string;
  sample: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  count?: number;
}

export const RASP_RULE: Record<SinkKind, string> = {
  sql: 'RASP-SQL-001',
  shell: 'RASP-SHELL-001',
  path: 'RASP-PATH-001',
  nosql: 'RASP-NOSQL-001',
  ssrf: 'RASP-SSRF-001',
  proto: 'RASP-PROTO-001',
};

export const RASP_FAIL_OPEN = 'RASP-FAIL-OPEN-001';

export class RaspBlockedError extends Error {
  readonly ruleId: string;
  constructor(ruleId: string) {
    super(`fullshield rasp blocked ${ruleId}`);
    this.name = 'RaspBlockedError';
    this.ruleId = ruleId;
  }
}
