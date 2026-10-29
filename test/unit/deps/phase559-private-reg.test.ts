import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { formatCliError } from '../../../src/cli/errors.js';
import { ALLOWED_HOSTS } from '../../../src/net/hosts.js';
import {
  matchOrgAdvisories,
  orgAdvisoryWithinCap,
  parseOrgAdvisoryDocument,
  parsePrivateRegistry,
  privateRegistryContactsNetwork,
  scanOrgAdvisories,
  ORG_ADVISORY_MAX_BYTES,
} from '../../../src/modules/deps/private-reg.js';

const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

function jsonOfSize(size: number): string {
  const head = '{"advisories":[],"note":"';
  const tail = '"}';
  const fill = size - Buffer.byteLength(head) - Buffer.byteLength(tail);
  return head + 'x'.repeat(fill) + tail;
}

describe('phase 559 private registry', () => {
  it('accepts https and refuses http, userinfo, and any network contact', () => {
    expect(parsePrivateRegistry('https://npm.example.com/path')).toBe('npm.example.com');
    expect(() => parsePrivateRegistry('http://npm.example.com')).toThrow(/FULLSHIELD_EXPERIMENTAL_PRIVATE_REG/);
    expect(() => parsePrivateRegistry('https://user:pass@npm.example.com')).toThrow(/FULLSHIELD_EXPERIMENTAL_PRIVATE_REG/);
    expect(formatCliError(new Error('deps.registry must be https with no userinfo (FULLSHIELD_EXPERIMENTAL_PRIVATE_REG)'))).toMatch(/FS-E021/);
    expect(privateRegistryContactsNetwork()).toBe(false);
    expect([...ALLOWED_HOSTS]).not.toContain('api.first.org');
    expect([...ALLOWED_HOSTS]).not.toContain('www.cisa.gov');
    expect([...ALLOWED_HOSTS]).not.toContain('npm.example.com');
  });

  it('rejects a bad url and a cache that is not an advisory list', () => {
    expect(() => parsePrivateRegistry('not a url')).toThrow(/FULLSHIELD_EXPERIMENTAL_PRIVATE_REG/);
    expect(() => parsePrivateRegistry('https://')).toThrow(/FULLSHIELD_EXPERIMENTAL_PRIVATE_REG/);
    expect(() => parseOrgAdvisoryDocument('not-json')).toThrow(/not JSON/);
    expect(() => parseOrgAdvisoryDocument('[]')).toThrow(/must be an object/);
    expect(() => parseOrgAdvisoryDocument('{"advisories":{}}')).toThrow(/must list advisories/);
    expect(() => parseOrgAdvisoryDocument('{"advisories":[null]}')).toThrow(/invalid/);
    expect(() => parseOrgAdvisoryDocument('{"advisories":[{}] }')).toThrow(/invalid/);
    expect(() => parseOrgAdvisoryDocument('{"advisories":[{"name":"a","version":"1","id":"x","severity":"nope","summary":"s"}]}')).toThrow(/invalid/);
  });

  it('accepts 1000000 bytes and rejects 1000001', () => {
    expect(orgAdvisoryWithinCap(ORG_ADVISORY_MAX_BYTES)).toBe(true);
    expect(orgAdvisoryWithinCap(ORG_ADVISORY_MAX_BYTES + 1)).toBe(false);
    expect(parseOrgAdvisoryDocument(jsonOfSize(ORG_ADVISORY_MAX_BYTES))).toEqual([]);
    expect(() => parseOrgAdvisoryDocument(jsonOfSize(ORG_ADVISORY_MAX_BYTES + 1))).toThrow(/1000000/);
  });

  it('matches an installed version from the local cache and stays silent when the file is missing', async () => {
    const findings = matchOrgAdvisories(
      [{ name: 'leftpad', version: '1.2.3' }],
      [{ name: 'leftpad', version: '1.2.3', id: 'ORG-1', severity: 'high', summary: 'internal' }],
    );
    expect(findings[0]?.ruleId).toBe('DEPS-ORG-ADV-001');
    expect(findings[0]?.message).toMatch(/local org cache/);
    expect(matchOrgAdvisories([{ name: 'leftpad', version: '9.9.9' }], [
      { name: 'leftpad', version: '1.2.3', id: 'ORG-1', severity: 'high', summary: 'internal' },
    ])).toEqual([]);

    const dir = await mkdtemp(join(tmpdir(), 'fullshield-org-'));
    dirs.push(dir);
    const cache = await mkdtemp(join(tmpdir(), 'fullshield-org-cache-'));
    dirs.push(cache);
    await writeFile(join(dir, 'package.json'), JSON.stringify({ dependencies: { leftpad: '1.2.3' } }), 'utf8');
    await mkdir(join(dir, 'node_modules', 'leftpad'), { recursive: true });
    await writeFile(join(dir, 'node_modules', 'leftpad', 'package.json'), JSON.stringify({ version: '1.2.3' }), 'utf8');
    expect(await scanOrgAdvisories(dir, cache)).toEqual([]);
    await writeFile(
      join(cache, 'org-advisories.json'),
      JSON.stringify({ advisories: [{ name: 'leftpad', version: '1.2.3', id: 'ORG-9', severity: 'low', summary: 'cached' }] }),
      'utf8',
    );
    const hit = await scanOrgAdvisories(dir, cache);
    expect(hit.map((row) => row.severity)).toEqual(['low']);
    await rm(join(dir, 'node_modules', 'leftpad', 'package.json'));
    await mkdir(join(dir, 'node_modules', 'leftpad', 'package.json'));
    expect(await scanOrgAdvisories(dir, cache)).toEqual([]);
  });
});
