import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  auditDiff,
  cyclonedxPurl,
  dedupeAdvisoryIds,
  dedupeAliases,
  fixedVersionForRange,
  laneFindings,
  laneRows,
  nestedOverrideKey,
  purlFor,
  severityFromCvss,
  withoutWithdrawn,
} from '../../../../../src/modules/deps/npm/lane-h.js';
import type { NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';

const FLAGS = [
  'FULLSHIELD_EXPERIMENTAL_NPM_OSV_RANGE',
  'FULLSHIELD_EXPERIMENTAL_NPM_OSV_WITHDRAWN',
  'FULLSHIELD_EXPERIMENTAL_NPM_OSV_CVSS',
  'FULLSHIELD_EXPERIMENTAL_NPM_OSV_ALIAS',
  'FULLSHIELD_EXPERIMENTAL_NPM_OSV_PURL',
  'FULLSHIELD_EXPERIMENTAL_NPM_FIX_NESTED',
  'FULLSHIELD_EXPERIMENTAL_NPM_SBOM_PURL',
  'FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF',
] as const;

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');

afterEach(() => {
  for (const flag of FLAGS) {delete process.env[flag];}
});

describe('lane H findings', () => {
  it('returns no findings when the lane flags are off', async () => {
    expect(laneRows).toEqual([]);
    expect(await laneFindings(cleanInput('{}'))).toEqual([]);
  });

  it('returns no findings for a clean app when every lane flag is on', async () => {
    for (const flag of FLAGS) {process.env[flag] = '1';}
    const manifestRaw = await readFile(join(cleanApp, 'package.json'), 'utf8');
    const findings = await laneFindings({
      cwd: cleanApp,
      files: ['package.json', 'package-lock.json', 'src/index.js'],
      manifestRaw,
      lockTexts: {},
      cacheDir: join(cleanApp, 'does-not-exist-cache'),
      offline: true,
    });
    expect(findings).toEqual([]);
  });
});

function cleanInput(manifestRaw: string): NpmDepthInput {
  return {
    cwd: cleanApp,
    files: ['package.json'],
    manifestRaw,
    lockTexts: {},
    cacheDir: join(cleanApp, 'does-not-exist-cache'),
    offline: true,
  };
}

describe('phase 243 fixed version by range type', () => {
  const gitOnly = [{
    ranges: [{ type: 'GIT', events: [{ introduced: '0', fixed: 'abc123deadbeef' }] }],
  }];

  it('does not invent a semver from a GIT range when the flag is on', () => {
    expect(fixedVersionForRange(gitOnly, true)).toBeUndefined();
    expect(fixedVersionForRange([{
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0', fixed: '1.2.3' }] }],
    }], true)).toBeUndefined();
  });

  it('still returns the cached SEMVER fixed version', () => {
    const affected = [{
      ranges: [
        { type: 'GIT', events: [{ introduced: '0', fixed: '9.9.9' }] },
        { type: 'SEMVER', events: [{ introduced: '0', fixed: '4.17.12' }, { fixed: '4.17.21' }] },
      ],
    }];
    expect(fixedVersionForRange(affected, true)).toBe('4.17.21');
    expect(fixedVersionForRange(gitOnly, false)).toBe('abc123deadbeef');
  });
});

describe('phase 244 withdrawn advisories', () => {
  const live = { id: 'GHSA-live', summary: 'still current' };
  const withdrawn = { id: 'GHSA-gone', withdrawn: '2024-01-15T00:00:00Z' };

  it('drops an advisory with a withdrawn timestamp when the flag is on', () => {
    expect(withoutWithdrawn([live, withdrawn], true).map((vuln) => vuln.id)).toEqual(['GHSA-live']);
  });

  it('keeps an advisory with no withdrawn field, and keeps withdrawn rows when the flag is off', () => {
    expect(withoutWithdrawn([live], true).map((vuln) => vuln.id)).toEqual(['GHSA-live']);
    expect(withoutWithdrawn([live, withdrawn], false).map((vuln) => vuln.id)).toEqual([
      'GHSA-live',
      'GHSA-gone',
    ]);
    expect(withoutWithdrawn([{ id: 'GHSA-blank', withdrawn: '' }], true).map((vuln) => vuln.id)).toEqual([
      'GHSA-blank',
    ]);
  });
});

describe('phase 245 CVSS severity', () => {
  it('maps a numeric CVSS v3 or v4 score with the documented cuts', () => {
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '9.0' }] }, true)).toBe('critical');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '10' }] }, true)).toBe('critical');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '8.9' }] }, true)).toBe('high');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '7' }] }, true)).toBe('high');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V4', score: '6.9' }] }, true)).toBe('medium');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V4', score: '4.0' }] }, true)).toBe('medium');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '3.9' }] }, true)).toBe('low');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '0.1' }] }, true)).toBe('low');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '0' }] }, true)).toBe('high');
    expect(severityFromCvss({
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    }, true)).toBe('high');
  });

  it('lets database_specific.severity win, and ignores CVSS when the flag is off', () => {
    expect(severityFromCvss({
      database_specific: { severity: 'HIGH' },
      severity: [{ type: 'CVSS_V3', score: '1.2' }],
    }, true)).toBe('high');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V3', score: '9.8' }] }, false)).toBe('high');
    expect(severityFromCvss({ database_specific: { severity: 'CRITICAL' } }, false)).toBe('critical');
    expect(severityFromCvss({ severity: [{ type: 'CVSS_V2', score: '9.8' }] }, true)).toBe('high');
  });
});

describe('phase 246 alias dedupe', () => {
  const mal = {
    id: 'MAL-2024-1',
    aliases: ['GHSA-alias-aaaa-bbbb'],
    affected: [{ package: { name: 'left-pad' }, versions: ['1.0.0'] }],
  };
  const ghsa = {
    id: 'GHSA-alias-aaaa-bbbb',
    aliases: ['CVE-2024-1000'],
    affected: [{ package: { name: 'left-pad' }, versions: ['1.0.0'] }],
  };
  const cve = {
    id: 'CVE-2024-1000',
    aliases: ['GHSA-alias-aaaa-bbbb'],
    affected: [{ package: { name: 'left-pad' }, versions: ['1.0.0'] }],
  };

  it('keeps one advisory and prefers MAL-, then GHSA-, then CVE-, then lexicographic', () => {
    const merged = dedupeAliases([cve, ghsa, mal], true);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.id).toBe('MAL-2024-1');
    expect(merged[0]?.references).toEqual(['CVE-2024-1000', 'GHSA-alias-aaaa-bbbb']);

    const ghsaWins = dedupeAliases([cve, ghsa], true);
    expect(ghsaWins.map((vuln) => vuln.id)).toEqual(['GHSA-alias-aaaa-bbbb']);
    expect(ghsaWins[0]?.references).toEqual(['CVE-2024-1000']);

    const lexical = dedupeAliases([
      { id: 'OSV-2020-2', aliases: ['ALIAS-1'] },
      { id: 'OSV-2020-1', aliases: ['ALIAS-1'] },
    ], true);
    expect(lexical.map((vuln) => vuln.id)).toEqual(['OSV-2020-1']);
    expect(lexical[0]?.references).toEqual(['OSV-2020-2']);
  });

  it('keeps two advisories when they share no alias, differ by version, or the flag is off', () => {
    const separate = dedupeAliases([
      { id: 'GHSA-one', aliases: ['CVE-2020-1'] },
      { id: 'GHSA-two', aliases: ['CVE-2020-2'] },
    ], true);
    expect(separate.map((vuln) => vuln.id)).toEqual(['GHSA-one', 'GHSA-two']);
    expect(separate.every((vuln) => vuln.references === undefined)).toBe(true);

    const versions = dedupeAliases([
      { id: 'GHSA-v', aliases: ['CVE-1'], affected: [{ versions: ['1.0.0'] }] },
      { id: 'CVE-1', aliases: ['GHSA-v'], affected: [{ versions: ['2.0.0'] }] },
    ], true);
    expect(versions.map((vuln) => vuln.id)).toEqual(['GHSA-v', 'CVE-1']);

    expect(dedupeAliases([cve, ghsa, mal], false)).toHaveLength(3);
  });
});

describe('phase 247 package url', () => {
  it('percent-encodes a scope slash and leaves an unscoped name alone', () => {
    expect(purlFor('@scope/name', '1.2.3')).toBe('pkg:npm/@scope%2Fname@1.2.3');
    expect(purlFor('lodash', '4.17.21')).toBe('pkg:npm/lodash@4.17.21');
    expect(purlFor('lodash', '4.17.21')).not.toContain('%2F');
  });

  it('dedupes a repeated advisory id from a batch and does not add a finding', () => {
    expect(dedupeAdvisoryIds(['GHSA-same', 'GHSA-same', 'CVE-other'])).toEqual(['GHSA-same', 'CVE-other']);
    expect(laneRows).toEqual([]);
  });
});

describe('phase 248 nested override proposal', () => {
  it('proposes parent>child for npm, pnpm, and yarn without editing a lockfile', () => {
    const fragment = nestedOverrideKey('express', 'qs', '6.11.0');
    expect(fragment).toEqual({
      overrides: { 'express>qs': '6.11.0' },
      pnpm: { overrides: { 'express>qs': '6.11.0' } },
      resolutions: { 'express>qs': '6.11.0' },
      notice: 'run npm install',
    });
    expect(fragment).not.toHaveProperty('packages');
    expect(fragment).not.toHaveProperty('lockfileVersion');
    expect(nestedOverrideKey('express', 'qs', undefined)).toBeUndefined();
  });

  it('keeps a direct bump on the package name and does not add a nested key', () => {
    const fragment = nestedOverrideKey('', 'express', '4.21.0');
    expect(fragment?.overrides).toEqual({ express: '4.21.0' });
    expect(JSON.stringify(fragment)).not.toContain('>');
    expect(fragment?.notice).toBeUndefined();
  });
});

describe('phase 249 CycloneDX purl', () => {
  it('adds a checksum when integrity is known and encodes a scoped name', () => {
    expect(cyclonedxPurl('@scope/name', '1.2.3', 'sha512-abc+/=')).toEqual({
      purl: 'pkg:npm/@scope%2Fname@1.2.3',
      checksum: { alg: 'SHA-512', content: 'abc+/=' },
    });
  });

  it('omits the checksum when integrity is absent and still returns the purl', () => {
    expect(cyclonedxPurl('lodash', '4.17.21')).toEqual({ purl: 'pkg:npm/lodash@4.17.21' });
    expect(cyclonedxPurl('lodash', '4.17.21')).not.toHaveProperty('checksum');
  });
});

describe('phase 250 audit diff', () => {
  const scan = [{
    ruleId: 'DEPS-VULN-001',
    references: ['GHSA-only-scan', 'CVE-2024-2000'],
  }];

  it('lists ids that are only in the audit file and ids that are only in the scan', () => {
    const diff = auditDiff({
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          version: '4.17.20',
          via: [{
            url: 'https://github.com/advisories/GHSA-only-audit',
            cves: ['CVE-2024-1000'],
          }],
        },
      },
    }, scan);
    expect(diff.onlyAudit).toEqual(['CVE-2024-1000', 'GHSA-only-audit']);
    expect(diff.onlyScan).toEqual(['CVE-2024-2000', 'GHSA-only-scan']);
    expect(diff.unmatched).toEqual([]);
  });

  it('prints both sets empty when the ids match, and does not invent ids', () => {
    const diff = auditDiff({
      vulnerabilities: {
        lodash: {
          version: '4.17.20',
          via: [{
            url: 'https://github.com/advisories/GHSA-only-scan',
            cves: ['CVE-2024-2000'],
          }],
        },
      },
    }, [
      ...scan,
      { ruleId: 'DEPS-MALICIOUS-001', references: ['MAL-2024-9999'] },
    ]);
    expect(diff).toEqual({ onlyAudit: [], onlyScan: [], unmatched: [] });
    expect(auditDiff({ metadata: { total: 0 } }, [])).toEqual({
      onlyAudit: [],
      onlyScan: [],
      unmatched: [],
    });
  });

  it('lists an audit advisory with no version as unmatched', () => {
    const diff = auditDiff({
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          via: [{ url: 'https://github.com/advisories/GHSA-no-version' }],
        },
      },
    }, [{ ruleId: 'DEPS-VULN-001', references: ['GHSA-no-version'] }]);
    expect(diff.onlyAudit).toEqual([]);
    expect(diff.unmatched).toEqual(['GHSA-no-version']);
    expect(diff.onlyScan).toEqual(['GHSA-no-version']);
  });
});
