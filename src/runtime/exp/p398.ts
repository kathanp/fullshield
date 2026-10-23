/**
 * Phase 398. Upload path and content type.
 * Off unless FULLSHIELD_EXPERIMENTAL_UPLOAD=1.
 * Does not inspect file bytes.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_UPLOAD';

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

export interface UploadFinding {
  ruleId: 'SAST-PATH-001' | 'SAST-UPLOAD-TYPE-001';
  severity: 'high';
  message: string;
}

export function uploadStatic(source: string): UploadFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: UploadFinding[] = [];
  if (/path\.join\(\s*\w+\s*,\s*(?:req\.file\.originalname|name)\s*\)/.test(source) && !source.includes('path.basename')) {
    findings.push({
      ruleId: 'SAST-PATH-001',
      severity: 'high',
      message: 'Upload filename is joined without basename.',
    });
  }
  const dangerousType = /text\/html|image\/svg\+xml/.test(source);
  const forcedSafe = /application\/octet-stream/.test(source);
  if (dangerousType && !forcedSafe) {
    findings.push({
      ruleId: 'SAST-UPLOAD-TYPE-001',
      severity: 'high',
      message: 'Uploaded file is served with a content type that can be text/html or image/svg+xml.',
    });
  }
  return findings;
}

function assertUploadAllow(types: readonly string[]): void {
  if (types.includes('text/html')) {
    throw new FsError('text/html cannot be allowlisted');
  }
}

export function uploadHook(filename: string, contentType: string, allow: readonly string[] = []): { reject: boolean } {
  if (!enabled()) {
    return { reject: false };
  }
  assertUploadAllow(allow);
  if (filename.includes('..') || filename.includes('\\') || filename.startsWith('/')) {
    return { reject: true };
  }
  if ((contentType === 'text/html' || contentType === 'image/svg+xml') && !allow.includes(contentType)) {
    return { reject: true };
  }
  return { reject: false };
}
