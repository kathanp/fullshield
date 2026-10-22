/**
 * Phase 456. Terraform text for the Node deploy.
 * Off unless FULLSHIELD_EXPERIMENTAL_TFNODE=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Parses an in-tree HCL subset. Does not download modules or run Terraform.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TFNODE';
export const TF_CIDR = 'CONFIG-TF-CIDR-001';
export const TF_ACL = 'CONFIG-TF-ACL-001';
export const TF_USERDATA = 'CONFIG-TF-USERDATA-001';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet?: string;
}

export interface PhaseEvent {
  kind: 'parser-failure';
  file: string;
  line: number;
  reason: string;
}

export interface TfResult {
  findings: PhaseFinding[];
  events: PhaseEvent[];
}

interface Block {
  kind: string;
  type: string;
  name: string;
  body: string;
  line: number;
}

function blocksOf(text: string): { blocks: Block[]; events: PhaseEvent[]; file: string } {
  const blocks: Block[] = [];
  const events: PhaseEvent[] = [];
  const lines = text.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? '';
    const header = /^(resource|data|module|dynamic)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{/.exec(line.trim());
    if (header === null) {
      i += 1;
      continue;
    }
    const kind = header[1] ?? '';
    const type = header[2] ?? '';
    const name = header[3] ?? '';
    let depth = 0;
    const body: string[] = [];
    const start = i;
    for (; i < lines.length; i += 1) {
      const current = lines[i] ?? '';
      depth += (current.match(/\{/g) ?? []).length;
      depth -= (current.match(/\}/g) ?? []).length;
      body.push(current);
      if (depth === 0) {
        break;
      }
    }
    if (kind === 'module' || kind === 'dynamic') {
      events.push({ kind: 'parser-failure', file: '', line: start + 1, reason: `${kind} is outside the HCL subset` });
    }
    blocks.push({ kind, type, name, body: body.join('\n'), line: start + 1 });
    i += 1;
  }
  return { blocks, events, file: '' };
}

function appBlocks(blocks: readonly Block[], packageName: string): Block[] {
  return blocks.filter((block) => block.kind === 'resource' && block.body.includes(packageName));
}

export function scanTerraform(file: string, text: string, packageName: string, baseline: readonly PhaseFinding[] = []): TfResult {
  if (!enabled()) {
    return { findings: [...baseline], events: [] };
  }
  const parsed = blocksOf(text);
  const apps = appBlocks(parsed.blocks, packageName);
  const connected = new Set<string>();
  for (const app of apps) {
    const refs = app.body.matchAll(/aws_security_group\.([A-Za-z0-9_]+)/g);
    for (const ref of refs) {
      if (ref[1] !== undefined) {
        connected.add(ref[1]);
      }
    }
  }
  const findings: PhaseFinding[] = [];
  for (const block of parsed.blocks) {
    if (block.kind !== 'resource') {
      continue;
    }
    const world = /0\.0\.0\.0\/0|::\/0/.test(block.body);
    const appPort = /from_port\s*=\s*3000/.test(block.body) || /to_port\s*=\s*3000/.test(block.body);
    if (world && appPort && (connected.has(block.name) || block.body.includes(packageName))) {
      findings.push({ ruleId: TF_CIDR, severity: 'high', file, line: block.line, message: 'ingress 0.0.0.0/0 on the app port' });
    }
    if (/acl\s*=\s*"public-read"/.test(block.body)) {
      const bucket = /aws_s3_bucket\.([A-Za-z0-9_]+)/.exec(block.body)?.[1];
      const passed = bucket !== undefined && apps.some((app) => app.body.includes(`aws_s3_bucket.${bucket}`));
      if (passed) {
        findings.push({ ruleId: TF_ACL, severity: 'high', file, line: block.line, message: 'public-read ACL on a bucket passed to the app' });
      }
    }
    if (block.body.includes('user_data') && SECRET.test(block.body)) {
      const token = SECRET.exec(block.body)?.[0] ?? '';
      findings.push({ ruleId: TF_USERDATA, severity: 'high', file, line: block.line, message: 'user_data literal', snippet: `${token.slice(0, 4)}****` });
    }
  }
  const events = parsed.events.map((event) => ({ ...event, file }));
  return { findings: [...baseline, ...findings], events };
}
