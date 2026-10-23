import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, scanGit, type GitReader } from '../../../src/phases/p335.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth',
  source: 'https://example.invalid/grammar',
  prefix: 'fsyn_',
  alphabet: 'A-Za-z0-9',
  length: 16,
  notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];

function gitObject(type: string, payload: Buffer): { sha: string; zlib: Buffer } {
  const raw = Buffer.concat([Buffer.from(`${type} ${String(payload.length)}\0`), payload]);
  return { sha: createHash('sha1').update(raw).digest('hex'), zlib: deflateSync(raw) };
}

function tree(entries: { name: string; sha: string }[]): Buffer {
  return Buffer.concat(entries.map((entry) => Buffer.concat([
    Buffer.from(`100644 ${entry.name}\0`),
    Buffer.from(entry.sha, 'hex'),
  ])));
}

function reader(files: Map<string, Buffer>): GitReader {
  return {
    read(path) {
      return files.get(path);
    },
    list() {
      return [];
    },
  };
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 335 git objects', () => {
  it('emits nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(scanGit(reader(new Map()), formats).findings).toEqual([]);
  });

  it('reports a blob reachable only from the reflog', () => {
    process.env[FLAG] = '1';
    const blob = gitObject('blob', Buffer.from(TOKEN));
    const treeObject = gitObject('tree', tree([{ name: 'secret.txt', sha: blob.sha }]));
    const commit = gitObject('commit', Buffer.from(`tree ${treeObject.sha}\n`));
    const files = new Map<string, Buffer>([
      [`.git/objects/${blob.sha.slice(0, 2)}/${blob.sha.slice(2)}`, blob.zlib],
      [`.git/objects/${treeObject.sha.slice(0, 2)}/${treeObject.sha.slice(2)}`, treeObject.zlib],
      [`.git/objects/${commit.sha.slice(0, 2)}/${commit.sha.slice(2)}`, commit.zlib],
      ['.git/logs/HEAD', Buffer.from(`${'0'.repeat(40)} ${commit.sha} A <a@example.invalid> 1 +0000\tcommit\n`)],
    ]);
    const result = scanGit(reader(files), formats);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.file).toContain(blob.sha);
    expect(result.findings[0]?.message).toContain('git-object');
    expect(result.findings[0]?.message).toContain('not in the working tree');
  });

  it('does not read an alternate, records a corrupt object, and does not import child_process', () => {
    process.env[FLAG] = '1';
    const files = new Map<string, Buffer>([
      ['.git/objects/info/alternates', Buffer.from('/outside/objects\n')],
      ['.git/logs/HEAD', Buffer.from(`${'0'.repeat(40)} ${'ab'.repeat(20)} A <a@example.invalid> 1 +0000\tcommit\n`)],
      [`.git/objects/ab/${'ab'.repeat(19)}`, Buffer.from('not-zlib')],
    ]);
    const fs = reader(files);
    const guarded: GitReader = {
      read(path) {
        if (path.startsWith('/outside')) {
          throw new Error('followed alternate');
        }
        return fs.read(path);
      },
      list(path) {
        return fs.list(path);
      },
    };
    const result = scanGit(guarded, formats);
    expect(result.events.some((event) => event.detail === 'alternate not followed')).toBe(true);
    expect(result.events.some((event) => event.detail === 'corrupt git object')).toBe(true);
    const source = readFileSync(new URL('../../../src/phases/p335.ts', import.meta.url), 'utf8');
    expect(source.includes('child_process')).toBe(false);
  });

  it('reads HEAD, packed-refs, and a stash, and stops when the byte budget is spent', () => {
    process.env[FLAG] = '1';
    const blob = gitObject('blob', Buffer.from(TOKEN));
    const other = gitObject('blob', Buffer.from('plain'));
    const tag = gitObject('tag', Buffer.from('object ' + blob.sha + '\n'));
    const brokenTree = gitObject('tree', Buffer.from('100644 short\0'));
    const commit = gitObject('commit', Buffer.from('parent abc\n'));
    const files = new Map<string, Buffer>([
      ['.git/HEAD', Buffer.from(blob.sha + '\n')],
      ['.git/packed-refs', Buffer.from(`# comment\n${blob.sha} refs/heads/secret\n${other.sha} refs/heads/other\n${brokenTree.sha} refs/heads/tree\n${commit.sha} refs/heads/commit\nnot-a-ref\n`)],
      ['.git/refs/stash', Buffer.from('zz\n')],
      ['.git/refs/heads/main', Buffer.from(brokenTree.sha + '\n')],
      ['.git/logs/HEAD', Buffer.from(`${'0'.repeat(40)} ${'0'.repeat(40)} A <a@example.invalid> 1\n${blob.sha} ${tag.sha} A <a@example.invalid> 1\n`)],
      ['.git/objects/info/alternates', Buffer.from('\n/outside\n')],
      [`.git/objects/${blob.sha.slice(0, 2)}/${blob.sha.slice(2)}`, blob.zlib],
      [`.git/objects/${other.sha.slice(0, 2)}/${other.sha.slice(2)}`, other.zlib],
      [`.git/objects/${tag.sha.slice(0, 2)}/${tag.sha.slice(2)}`, tag.zlib],
      [`.git/objects/${brokenTree.sha.slice(0, 2)}/${brokenTree.sha.slice(2)}`, brokenTree.zlib],
      [`.git/objects/${commit.sha.slice(0, 2)}/${commit.sha.slice(2)}`, commit.zlib],
    ]);
    const result = scanGit(reader(files), formats);
    expect(result.findings.some((finding) => finding.witness === 'git-object')).toBe(true);
    expect(result.events.some((event) => event.detail === 'alternate not followed')).toBe(true);
    const budget = scanGit(reader(new Map([
      ['.git/packed-refs', Buffer.from(`${blob.sha} refs/heads/secret\n${other.sha} refs/heads/other\n`)],
      [`.git/objects/${blob.sha.slice(0, 2)}/${blob.sha.slice(2)}`, blob.zlib],
      [`.git/objects/${other.sha.slice(0, 2)}/${other.sha.slice(2)}`, other.zlib],
    ])), formats, 0);
    expect(budget.findings).toHaveLength(1);
    expect(budget.events.some((event) => event.detail === 'git object fuel exhausted')).toBe(true);
    const ref = scanGit(reader(new Map([
      ['.git/HEAD', Buffer.from('ref: refs/heads/main\n')],
      ['.git/refs/heads/main', Buffer.from(blob.sha + '\n')],
      [`.git/objects/${blob.sha.slice(0, 2)}/${blob.sha.slice(2)}`, blob.zlib],
      ['.git/objects/info/alternates', Buffer.from('')],
    ])), formats);
    expect(ref.findings).toHaveLength(1);
    expect(ref.claimedClean).toBe(true);
  });

  it('records a missing object, a corrupt header, and a pack that is not a pack', () => {
    process.env[FLAG] = '1';
    const loose = deflateSync(Buffer.from('nosep'));
    const sha = 'cd'.repeat(20);
    const missing = 'ab'.repeat(20);
    const files = new Map<string, Buffer>([
      ['.git/HEAD', Buffer.from(`${sha}\n`)],
      ['.git/packed-refs', Buffer.from(`${missing} refs/heads/missing\n`)],
      [`.git/objects/${sha.slice(0, 2)}/${sha.slice(2)}`, loose],
    ]);
    const listed = reader(files);
    const result = scanGit({
      read: (path) => listed.read(path),
      list: (path) => {
        if (path.endsWith('pack')) {
          return ['good.pack', 'skip.idx', 'bad.pack', 'gone.pack'];
        }
        throw new Error('list failed');
      },
    }, formats);
    expect(result.events.some((event) => event.detail === 'corrupt git object')).toBe(true);
    expect(result.claimedClean).toBe(false);
    const packs = scanGit({
      read: (path) => {
        if (path.endsWith('good.pack')) {return Buffer.from('PACKxxxx');}
        if (path.endsWith('bad.pack')) {return Buffer.from('XXXX');}
        if (path.endsWith('short.pack')) {return Buffer.from('P');}
        return undefined;
      },
      list: () => ['good.pack', 'bad.pack', 'short.pack', 'gone.pack', 'note.txt'],
    }, formats);
    expect(packs.events.filter((event) => event.detail === 'corrupt pack').length).toBeGreaterThan(0);
    expect(scanGit({
      read: () => undefined,
      list: () => { throw new Error('no pack'); },
    }, formats).events).toEqual([]);
  });
});
