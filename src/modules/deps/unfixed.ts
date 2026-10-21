import { readFile } from 'node:fs/promises';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { registryCachePath } from '../../provenance/index.js';
import type { OsvHit } from './osv.js';
import { isMaliciousAdvisory } from './osv.js';
import { classifyReachability, type ReachabilityContext } from './reachability.js';
import { minFixedVersion } from './semver.js';

const STALE_MS = 730 * 24 * 60 * 60 * 1000;

const REMEDIATION = 'Decide whether to keep this dependency. FullShield does not name a replacement.';

async function publishedAt(cacheDir: string, name: string, version: string): Promise<string | undefined> {
  try {
    const raw = JSON.parse(await readFile(registryCachePath(cacheDir, name), 'utf8')) as {
      packument?: { time?: Record<string, string> };
    };
    const iso = raw.packument?.time?.[version];
    return typeof iso === 'string' ? iso : undefined;
  } catch {
    return undefined;
  }
}

/** Production dependency, no fixed version, last publish older than 730 days. Unknown dates are skipped. */
export async function unfixedFindings(
  hits: readonly OsvHit[],
  directProd: ReadonlySet<string>,
  ctx: ReachabilityContext,
  cacheDir: string,
  now = Date.now(),
): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const hit of hits) {
    if (!directProd.has(hit.pkg.name)) {continue;}
    for (const vuln of hit.vulns) {
      if (isMaliciousAdvisory(vuln)) {continue;}
      if (minFixedVersion(vuln.affected ?? []) !== undefined) {continue;}
      const iso = await publishedAt(cacheDir, hit.pkg.name, hit.pkg.version);
      if (iso === undefined) {continue;}
      const published = Date.parse(iso);
      if (!Number.isFinite(published) || now - published <= STALE_MS) {continue;}
      const snippet = `${hit.pkg.name}@${hit.pkg.version}`;
      const classified = classifyReachability(hit.pkg.name, ctx.productionUsage, ctx.graph);
      out.push({
        id: makeFindingId('DEPS-UNFIXED-001', 'package.json', `${snippet}|${vuln.id}`),
        ruleId: 'DEPS-UNFIXED-001',
        module: 'deps',
        title: `Unfixed dependency ${snippet}`,
        severity: 'medium',
        confidence: 'high',
        file: 'package.json',
        snippet,
        message: `${snippet} is affected by ${vuln.id} and OSV lists no fixed version. The registry publish date is ${iso}.`,
        remediation: REMEDIATION,
        references: [vuln.id],
        reachability: classified.reachability,
      });
    }
  }
  return out;
}
