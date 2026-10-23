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

  it('reports privileged containers, token mounts, labels, and unrendered Helm without a secret', () => {
    process.env[FLAG] = '1';
    try {
      const deploy = `apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: demo
spec:
  template:
    spec:
      automountServiceAccountToken: true
      containers:
        - name: app
          image: node:20
          command: ["node", "server.js"]
          args: ["demo"]
          securityContext:
            privileged: true
            runAsNonRoot: false
          resources:
            limits:
              memory: 128Mi
          volumeMounts:
            - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
            - "not-a-mount"
        - null
      volumes:
        - name: empty
`;
      const result = scanManifests('deploy.yaml', deploy, 'demo');
      expect(result.findings.some((row) => row.ruleId === 'CONFIG-K8S-PRIVILEGED-001')).toBe(true);
      expect(result.findings.some((row) => row.ruleId === 'CONFIG-K8S-SATOKEN-001' && row.severity === 'high')).toBe(true);
      expect(result.findings.some((row) => row.ruleId === K8S_ROOT && row.severity === 'medium')).toBe(true);
      expect(result.findings.some((row) => row.ruleId === K8S_MEM)).toBe(false);
      expect(result.findings.some((row) => row.ruleId === K8S_HOSTPATH)).toBe(false);

      const labeled = `apiVersion: v1
kind: Pod
metadata:
  labels:
    app.kubernetes.io/name: node:20
spec:
  automountServiceAccountToken: true
  containers:
    - name: app
      image: redis
      securityContext:
        runAsUser: 1000
      volumeMounts: "nope"
  volumes: nope
`;
      const info = scanManifests('pod.yaml', labeled, 'demo');
      expect(info.findings.some((row) => row.ruleId === 'CONFIG-K8S-SATOKEN-001' && row.severity === 'info')).toBe(true);
      expect(info.findings.some((row) => row.ruleId === K8S_ROOT)).toBe(false);

      const bare = scanManifests('pod.yaml', 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: node:20\n', 'demo');
      expect(bare.findings.some((row) => row.ruleId === K8S_MEM)).toBe(true);
      expect(bare.findings.some((row) => row.ruleId === K8S_ROOT)).toBe(false);

      const helm = scanManifests('chart.yaml', 'image: {{ .Values.image }}\n', 'demo');
      expect(helm.events).toHaveLength(1);
      expect(helm.findings.some((row) => row.ruleId === K8S_SECRET)).toBe(false);
      expect(scanManifests('pod.yaml', 'just a string\n---\n', 'demo').findings).toEqual([]);
      const noContainers = 'apiVersion: v1\nkind: Pod\nmetadata:\n  labels:\n    app: demo\n    note: skip\nspec: {}\n';
      expect(scanManifests('pod.yaml', noContainers, 'demo').findings).toEqual([]);
    } finally {
      delete process.env[FLAG];
    }
  });
});
