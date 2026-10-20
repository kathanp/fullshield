import type { Finding } from '../../core/finding.js';
import { configFinding } from './finding.js';

export function scanPackageScripts(file: string, text: string): Finding[] {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof raw !== 'object' || raw === null) {return [];}
  const findings: Finding[] = [];
  const record = raw as Record<string, unknown>;

  const scripts = record.scripts;
  if (scripts !== undefined && typeof scripts === 'object' && scripts !== null) {
    for (const name of ['preinstall', 'postinstall']) {
      if (name in scripts) {
        findings.push(
          configFinding(
            'CONFIG-INSTALLSCRIPT-001',
            `${name} script in package.json`,
            'info',
            file,
            `This package.json declares a ${name} script.`,
            'Avoid install scripts; they are a common supply-chain vector.',
          ),
        );
      }
    }
  }

  const packages = record.packages;
  if (packages !== undefined && typeof packages === 'object' && packages !== null) {
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      if (key === '' || typeof value !== 'object' || value === null) {continue;}
      if ((value as { hasInstallScript?: unknown }).hasInstallScript === true) {
        findings.push(
          configFinding(
            'CONFIG-INSTALLSCRIPT-001',
            'Dependency declares an install script',
            'info',
            file,
            `${key} has hasInstallScript in the lockfile.`,
            'Review install scripts before installing; prefer packages without them.',
          ),
        );
      }
    }
  }
  return findings;
}
