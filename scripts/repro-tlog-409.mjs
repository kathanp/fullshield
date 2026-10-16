#!/usr/bin/env node
/**
 * Run npm 12.2.0's real TLogClient against a Rekor 409.
 * Does not publish and does not contact Rekor.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'fullshield-tlog-'));
try {
  const packed = spawnSync('npm', ['pack', 'npm@12.2.0', '--pack-destination', dir], {
    encoding: 'utf8',
  });
  if (packed.status !== 0) {
    console.error(packed.stdout, packed.stderr);
    process.exit(1);
  }
  const tarball = join(dir, 'npm-12.2.0.tgz');
  const tar = spawnSync('tar', ['-xzf', tarball, '-C', dir], { encoding: 'utf8' });
  if (tar.status !== 0) {
    console.error(tar.stderr);
    process.exit(1);
  }
  const require = createRequire(join(dir, 'package/package.json'));
  const { TLogClient } = require('@sigstore/sign/dist/witness/tlog/client.js');
  const { HTTPError } = require('@sigstore/sign/dist/external/error.js');
  const uuid = '108e9186e8c5677afe7d392d1741a4cc34d624d765618d5d7cff767458ec9671f2b858fccf803918';
  const message = `an equivalent entry already exists in the transparency log with UUID ${uuid}`;

  function client(fetchOnConflict) {
    const created = new TLogClient({ rekorBaseURL: 'https://rekor.sigstore.dev', fetchOnConflict });
    created.rekor.createEntry = async () => {
      throw new HTTPError({
        status: 409,
        message,
        location: `https://rekor.sigstore.dev/api/v1/log/entries/${uuid}`,
      });
    };
    created.rekor.getEntry = async (id) => ({ uuid: id, recovered: true });
    return created;
  }

  try {
    await client(false).createEntry({});
    console.error('fetchOnConflict false did not throw');
    process.exit(1);
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String(err.code) : '';
    const text = err instanceof Error ? err.message : String(err);
    console.log(`fetchOnConflict false: ${code} ${text}`);
    if (code !== 'TLOG_CREATE_ENTRY_ERROR' || !text.includes('(409)')) process.exit(1);
  }

  const got = await client(true).createEntry({});
  console.log(`fetchOnConflict true: ${JSON.stringify(got)}`);
  if (got.uuid !== uuid || got.recovered !== true) process.exit(1);
  console.log('PASS');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
