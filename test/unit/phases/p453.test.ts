import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { FLAG, K8S_HOSTPATH, K8S_MEM, K8S_ROOT, K8S_SECRET, scanManifests } from '../../../src/phases/p453.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const token = `AKIA${'Z'.repeat(16)}`;

const rootUser = `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: node:20
      securityContext:
        runAsUser: 0
`;

describe('phase 453', () => {
  it('reports runAsUser 0, hostPath, and a missing memory limit', () => {
    process.env[FLAG] = '1';
    const result = scanManifests('pod.yaml', `${rootUser}      volumeMounts: []\n  volumes:\n    - name: data\n      hostPath:\n        path: /data\n`, 'demo');
    expect(result.findings.some((row) => row.ruleId === K8S_ROOT)).toBe(true);
    expect(result.findings.some((row) => row.ruleId === K8S_HOSTPATH)).toBe(true);
    expect(result.findings.some((row) => row.ruleId === K8S_MEM && row.severity === 'info')).toBe(true);
  });

  it('stays quiet for runAsNonRoot, a comment, and an unrelated manifest', () => {
    process.env[FLAG] = '1';
    const nonRoot = scanManifests('pod.yaml', rootUser.replace('runAsUser: 0', 'runAsNonRoot: true'), 'demo');
    expect(nonRoot.findings.some((row) => row.ruleId === K8S_ROOT)).toBe(false);
    const comment = scanManifests('pod.yaml', `# demo\napiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: redis\n`, 'demo');
    expect(comment.findings).toEqual([]);
    const other = scanManifests('pod.yaml', 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: redis\n      securityContext:\n        runAsUser: 0\n', 'demo');
    expect(other.findings).toEqual([]);
  });

  it('emits a Helm event and still reports a token', () => {
    process.env[FLAG] = '1';
    const result = scanManifests('chart.yaml', `image: {{ .Values.image }}\nTOKEN: ${token}\n`, 'demo');
    expect(result.events).toHaveLength(1);
    expect(result.findings.some((row) => row.ruleId === K8S_SECRET)).toBe(true);
    expect(JSON.stringify(result.findings)).not.toContain(token);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'pod.yaml', line: 1, message: 'kept' }];
    expect(scanManifests('pod.yaml', rootUser, 'demo', baseline).findings).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p453.ts'), 'utf8');
    expect(src.includes('KUBECONFIG')).toBe(false);
  });
});
