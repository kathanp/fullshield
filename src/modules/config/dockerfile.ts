import type { Finding } from '../../core/finding.js';
import { configFinding } from './finding.js';

export function scanDockerfile(file: string, text: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  let sawUser = false;
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    const from = /^FROM\s+(\S+)/i.exec(trimmed);
    if (from?.[1] !== undefined && /:latest\b/i.test(from[1])) {
      findings.push(
        configFinding(
          'CONFIG-DOCKER-LATEST-001',
          'Dockerfile uses a :latest tag',
          'medium',
          file,
          `FROM ${from[1]} pins no version; rebuilds are not reproducible.`,
          'Pin the image to a digest or a specific version tag.',
          index + 1,
        ),
      );
    }
    const env = /^ENV\s+([A-Za-z_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Za-z0-9_]*)\s*=\s*(\S+)/i.exec(trimmed);
    if (env?.[1] !== undefined && env[2] !== undefined && env[2] !== '""' && env[2] !== "''") {
      findings.push(
        configFinding(
          'CONFIG-DOCKER-ENV-001',
          'Secret assigned in Dockerfile ENV',
          'high',
          file,
          `${env[1]} is baked into the image via ENV.`,
          'Pass secrets at runtime (or a secret store); never ENV them into the image.',
          index + 1,
        ),
      );
    }
    if (/^USER\s+/i.test(trimmed)) {
      const user = trimmed.slice(5).trim();
      if (user === 'root' || user === '0') {
        findings.push(
          configFinding(
            'CONFIG-DOCKER-ROOT-001',
            'Dockerfile runs as root',
            'medium',
            file,
            `USER ${user} runs the container as root.`,
            'Add a non-root USER instruction.',
            index + 1,
          ),
        );
      }
      sawUser = true;
    }
  });
  if (!sawUser) {
    findings.push(
      configFinding(
        'CONFIG-DOCKER-ROOT-001',
        'Dockerfile runs as root',
        'medium',
        file,
        'No USER instruction; the container defaults to root.',
        'Add a non-root USER instruction.',
      ),
    );
  }
  return findings;
}
