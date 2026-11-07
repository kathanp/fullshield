import type { Finding } from '../core/finding.js';

export interface LlmScanOptions {
  experimental?: boolean;
}

/** LLM-001 through LLM-005 are not reported. */
export function scanLlmApp(dir: string, opts: LlmScanOptions = {}): Finding[] {
  void dir;
  void opts;
  return [];
}
