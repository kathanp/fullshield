import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();

function git(dir: string, args: string[]): void {
  execFileSync('git', args, {
    cwd: dir,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'quality',
      GIT_AUTHOR_EMAIL: 'quality@example.com',
      GIT_COMMITTER_NAME: 'quality',
      GIT_COMMITTER_EMAIL: 'quality@example.com',
    },
  });
}

describe('phase 94 quality gate', () => {
  it('fails Q1, Q4, Q6, and Q8 for any, an unused export, a missing FS-E, and a literal fetch', () => {
    const dir = mkdtempSync(join(root, '.quality-tmp-'));
    try {
      git(dir, ['init', '-b', 'next']);
      mkdirSync(join(dir, 'src'));
      mkdirSync(join(dir, 'docs'));
      mkdirSync(join(dir, 'quality'));
      writeFileSync(join(dir, 'package.json'), `${JSON.stringify({
        name: 'quality-fixture',
        type: 'module',
        exports: { '.': './src/index.ts' },
      }, null, 2)}\n`);
      writeFileSync(join(dir, 'tsconfig.json'), `${JSON.stringify({
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          noEmit: true,
          types: ['node'],
        },
        include: ['src'],
      }, null, 2)}\n`);
      writeFileSync(join(dir, 'src', 'index.ts'), 'export const ok = 1;\n');
      writeFileSync(join(dir, 'docs', 'errors.md'), '# errors\n\nFS-E001 is the only code.\n');
      writeFileSync(join(dir, 'quality', 'baseline.json'), `${JSON.stringify({
        q2: { 'src/index.ts': 0, 'src/bad.ts': 20 },
        q3: 0,
        q4: [],
        q6Bare: [],
        q6Undocumented: [],
        q7Runtime: [],
        q8: [],
        flags: [],
        ruleIds: [],
      }, null, 2)}\n`);
      git(dir, ['add', '.']);
      git(dir, ['commit', '-m', 'base']);
      git(dir, ['checkout', '-b', 'phase-bad']);
      writeFileSync(join(dir, 'src', 'bad.ts'), [
        'export function leftover(input: any): string {',
        "  fetch('https://example.com');",
        "  throw new Error('FS-E999 missing');",
        '  return input;',
        '}',
        '',
      ].join('\n'));
      git(dir, ['add', 'src/bad.ts']);
      git(dir, ['commit', '-m', 'bad']);
      const result = spawnSync(process.execPath, [join(root, 'scripts', 'quality.mjs'), '--root', dir, '--fixture'], {
        cwd: root,
        encoding: 'utf8',
      });
      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(1);
      const failed = result.stdout.split('\n')
        .filter((line) => line.includes('\tfail\t'))
        .map((line) => line.split('\t')[0]);
      expect(failed).toEqual(['Q1', 'Q4', 'Q6', 'Q8']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('fails Q2 at 1513 when the recorded baseline is 1512', () => {
    const dir = mkdtempSync(join(root, '.quality-tmp-'));
    try {
      git(dir, ['init', '-b', 'next']);
      mkdirSync(join(dir, 'src'));
      mkdirSync(join(dir, 'docs'));
      mkdirSync(join(dir, 'quality'));
      writeFileSync(join(dir, 'package.json'), `${JSON.stringify({
        name: 'quality-fixture',
        type: 'module',
        exports: { '.': './src/hot.ts' },
      }, null, 2)}\n`);
      writeFileSync(join(dir, 'tsconfig.json'), `${JSON.stringify({
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          noEmit: true,
          types: ['node'],
        },
        include: ['src'],
      }, null, 2)}\n`);
      writeFileSync(join(dir, 'docs', 'errors.md'), '# errors\n\nFS-E001 is the only code.\n');
      const lines = ['export const values = ['];
      for (let i = 0; i < 1513; i += 1) lines.push('  0 as any,');
      lines.push('];', '');
      writeFileSync(join(dir, 'src', 'hot.ts'), lines.join('\n'));
      writeFileSync(join(dir, 'quality', 'baseline.json'), `${JSON.stringify({
        q2: { 'src/hot.ts': 1512 },
        q3: 0,
        q4: [],
        q6Bare: [],
        q6Undocumented: [],
        q7Runtime: [],
        q8: [],
        flags: [],
        ruleIds: [],
      }, null, 2)}\n`);
      git(dir, ['add', '.']);
      git(dir, ['commit', '-m', 'base']);
      const result = spawnSync(process.execPath, [join(root, 'scripts', 'quality.mjs'), '--root', dir, '--fixture'], {
        cwd: root,
        encoding: 'utf8',
      });
      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(1);
      const q2 = result.stdout.split('\n').find((line) => line.startsWith('Q2\t'));
      expect(q2).toBe('Q2\tsrc\tfail\t1513\t1512');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
