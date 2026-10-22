import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const STRATA = new Set([
  'express',
  'fastify',
  'nest',
  'next',
  'koa-hono',
  'monorepo',
  'electron',
  'ts-heavy',
  'js-only',
]);

const SHA = /^[0-9a-f]{40}$/;
const TARGET = 50;

function fail(message) {
  console.error(message);
  process.exit(1);
}

const argv = process.argv.slice(2);
if (argv.some((arg) => /install|npm|yarn|pnpm|execute|node_modules/i.test(arg))) {
  fail('realworld-v2 refuses install and execute');
}

const file = resolve(argv.find((arg) => arg.endsWith('.json')) ?? 'bench/realworld-v2.json');
const raw = JSON.parse(readFileSync(file, 'utf8'));
const repos = Array.isArray(raw.repos) ? raw.repos : null;
if (repos === null) {fail('repos must be an array');}

const names = new Set();
const counts = {};
for (const row of repos) {
  if (typeof row.name !== 'string' || row.name.length === 0) {fail('missing name');}
  if (names.has(row.name)) {fail(`duplicate name ${row.name}`);}
  names.add(row.name);
  if (typeof row.repo !== 'string' || !row.repo.startsWith('https://github.com/')) {fail(`bad repo ${row.name}`);}
  if (typeof row.sha !== 'string' || !SHA.test(row.sha)) {fail(`bad sha ${row.name}`);}
  if (!STRATA.has(row.stratum)) {fail(`bad stratum ${row.name}`);}
  counts[row.stratum] = (counts[row.stratum] ?? 0) + 1;
}

for (const stratum of STRATA) {
  if ((counts[stratum] ?? 0) === 0) {fail(`empty stratum ${stratum}`);}
}

console.log(`pins ${repos.length}`);
for (const stratum of STRATA) {console.log(`${stratum} ${counts[stratum]}`);}
if (repos.length < TARGET) {console.log(`gap ${TARGET - repos.length}`);}
