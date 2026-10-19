/**
 * Phase 87. registry.npmjs.org only. Missing data stays unknown.
 */

export interface ProvenanceSignal {
  name: string;
  version: string;
  kind: 'provenance-regression' | 'publisher-change' | 'new-release' | 'unknown';
  detail: string;
}

export interface PackumentVersion {
  name: string;
  version: string;
  time?: string;
  publisher?: string;
  hasProvenance?: boolean;
  previousPublishers?: string[];
  previousHadProvenance?: boolean;
}

const HOST = 'registry.npmjs.org';

export function provenanceFromPackument(row: PackumentVersion, now = Date.now(), minAgeHours = 72): ProvenanceSignal[] {
  if (row.hasProvenance === undefined && row.publisher === undefined && row.time === undefined) {
    return [{ name: row.name, version: row.version, kind: 'unknown', detail: 'registry data missing' }];
  }
  const signals: ProvenanceSignal[] = [];
  if (row.previousHadProvenance === true && row.hasProvenance === false) {
    signals.push({
      name: row.name,
      version: row.version,
      kind: 'provenance-regression',
      detail: `${row.name}@${row.version} has no provenance attestation and an earlier version did`,
    });
  }
  if (
    row.publisher !== undefined &&
    row.previousPublishers !== undefined &&
    row.previousPublishers.length > 0 &&
    !row.previousPublishers.includes(row.publisher)
  ) {
    signals.push({
      name: row.name,
      version: row.version,
      kind: 'publisher-change',
      detail: `${row.name}@${row.version} was published by ${row.publisher}, who published none of the previous versions`,
    });
  }
  if (row.time !== undefined) {
    const published = Date.parse(row.time);
    if (Number.isFinite(published) && now - published < minAgeHours * 60 * 60 * 1000) {
      signals.push({
        name: row.name,
        version: row.version,
        kind: 'new-release',
        detail: `${row.name}@${row.version} was published within ${minAgeHours} hours`,
      });
    }
  }
  return signals;
}

export async function fetchPackument(
  name: string,
  fetchImpl: typeof fetch = fetch,
): Promise<PackumentVersion | undefined> {
  const url = `https://${HOST}/${encodeURIComponent(name)}`;
  const response = await fetchImpl(url);
  if (!response.ok) return undefined;
  const body = (await response.json()) as {
    'dist-tags'?: { latest?: string };
    time?: Record<string, string>;
    versions?: Record<string, { _npmUser?: { name?: string }; dist?: { attestations?: unknown } }>;
  };
  const version = body['dist-tags']?.latest;
  if (version === undefined) return undefined;
  const versions = Object.keys(body.versions ?? {}).filter((item) => item !== version);
  const current = body.versions?.[version];
  const previous = versions.slice(-10).map((item) => body.versions?.[item]);
  return {
    name,
    version,
    time: body.time?.[version],
    publisher: current?._npmUser?.name,
    hasProvenance: current?.dist?.attestations != null,
    previousPublishers: previous.map((item) => item?._npmUser?.name).filter((item): item is string => item !== undefined),
    previousHadProvenance: previous.some((item) => item?.dist?.attestations != null),
  };
}

export function assertRegistryHost(url: string): void {
  const host = new URL(url).host;
  if (host !== HOST) throw new Error(`provenance lookup refused host ${host} (FULLSHIELD_EXPERIMENTAL_PROVENANCE)`);
}
