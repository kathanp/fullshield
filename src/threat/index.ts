import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

export interface ThreatRoute {
  method: string;
  path: string;
  file: string;
  auth?: boolean;
}

export interface StrideRow {
  element: string;
  spoofing: string;
  tampering: string;
  repudiation: string;
  infoDisclosure: string;
  denialOfService: string;
  elevation: string;
}

export interface ThreatModel {
  skipped?: boolean;
  routes: ThreatRoute[];
  stores: string[];
  egress: string[];
  stride: StrideRow[];
  mermaid: string;
}

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) {return out;}
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', 'dist', '.git'].includes(entry.name)) {continue;}
      walk(full, out);
    } else if (entry.isFile() && /\.[cm]?[jt]sx?$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

export function buildThreatModel(dir: string, opts: { experimental?: boolean } = {}): ThreatModel {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM !== '1') {
    return { skipped: true, routes: [], stores: [], egress: [], stride: [], mermaid: '' };
  }
  const routes: ThreatRoute[] = [];
  const stores = new Set<string>();
  const egress = new Set<string>();
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    return { routes, stores: [], egress: [], stride: [], mermaid: 'flowchart LR\n' };
  }
  for (const file of walk(dir)) {
    const rel = relative(dir, file) || file;
    const text = readFileSync(file, 'utf8');
    const routeRe = /app\.(get|post|put|patch|delete|use)\(\s*['"]([^'"]+)['"]/g;
    let m: RegExpExecArray | null;
    while ((m = routeRe.exec(text)) !== null) {
      routes.push({
        method: (m[1] ?? 'get').toUpperCase(),
        path: m[2] ?? '/',
        file: rel,
        auth: /auth|requireUser|requireAuth/.test(text),
      });
    }
    if (/sqlite|mongodb|postgres|mysql|createPool|DatabaseSync/.test(text)) {stores.add(rel);}
    const urlRe = /https?:\/\/[^\s'"[`]+/g;
    while ((m = urlRe.exec(text)) !== null) {egress.add(m[0] ?? '');}
  }
  const stride: StrideRow[] = routes.slice(0, 20).map((r) => ({
    element: `${r.method} ${r.path}`,
    spoofing: r.auth ? 'auth middleware present' : 'no auth seen',
    tampering: 'input reaches handler',
    repudiation: 'check access logs',
    infoDisclosure: 'review response bodies',
    denialOfService: 'no rate-limit inferred',
    elevation: r.auth ? 'review authorization' : 'unauthenticated route',
  }));
  const mermaid = [
    'flowchart LR',
    '  client[Client] --> app[App]',
    ...routes.slice(0, 12).map((r, i) => `  app --> r${i}["${r.method} ${r.path}"]`),
    ...[...stores].slice(0, 6).map((s, i) => `  app --> s${i}["store ${s}"]`),
  ].join('\n');
  return { routes, stores: [...stores], egress: [...egress], stride, mermaid };
}
