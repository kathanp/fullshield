#!/usr/bin/env node
/**
 * Scan every git blob in history with the secrets module.
 * Fake concatenated fixtures are expected; complete-looking keys are reported.
 */
import { execSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cwd = dirname(dirname(fileURLToPath(import.meta.url)));
const { scanTextForSecrets } = await import(pathToFileURL(join(cwd, 'dist', 'index.js')).href);

const commits = execSync('git rev-list --all', { encoding: 'utf8', cwd })
  .trim()
  .split('\n')
  .filter(Boolean);

const hits = [];
const skipName = /(^|\/)(\.git|node_modules|dist|coverage)\//;

for (const sha of commits) {
  const names = execSync(`git ls-tree -r --name-only ${sha}`, {
    encoding: 'utf8',
    cwd,
  })
    .trim()
    .split('\n')
    .filter((n) => n.length > 0 && !skipName.test(n));
  for (const name of names) {
    if (/\.(png|jpg|jpeg|gif|webp|woff2?|zip|tgz|gz)$/i.test(name)) continue;
    let text = '';
    try {
      text = execSync(`git show ${sha}:${name}`, {
        encoding: 'utf8',
        maxBuffer: 20 * 1024 * 1024,
        cwd,
      });
    } catch {
      continue;
    }
    const findings = scanTextForSecrets(name, text);
    for (const f of findings) {
      hits.push({
        sha,
        file: name,
        ruleId: f.ruleId,
        line: f.line,
        snippet: f.snippet,
      });
    }
  }
}

const unique = new Map();
for (const h of hits) {
  const key = `${h.file}|${h.ruleId}|${h.snippet ?? ''}`;
  if (!unique.has(key)) unique.set(key, { ...h, commits: 1 });
  else unique.get(key).commits += 1;
}

console.log(JSON.stringify({ commits: commits.length, rawHits: hits.length, unique: [...unique.values()] }, null, 2));
