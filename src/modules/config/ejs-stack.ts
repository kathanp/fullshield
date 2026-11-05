import type { Finding } from '../../core/finding.js';
import { configFinding } from './finding.js';
import { isSampleConfigPath } from './sample-path.js';

const PRINTED_STACK = /<%[-=][^%]*\b(?:error|err)\.stack\b/;

/** `<%= error.stack %>` and `<%- err.stack %>` leak internals. A comment does not. */
export function ejsStackFindings(file: string, source: string): Finding[] {
  if (!file.endsWith('.ejs') || isSampleConfigPath(file)) {return [];}
  const findings: Finding[] = [];
  source.split(/\r?\n/).forEach((line, index) => {
    if (!PRINTED_STACK.test(line)) {return;}
    findings.push(
      configFinding(
        'CONFIG-ERRSTACK-001',
        'Error stack leaked to the client',
        'medium',
        file,
        'error.stack is printed in an EJS template and can leak internals.',
        'Log the stack server-side and render a generic error message.',
        index + 1,
      ),
    );
  });
  return findings;
}
