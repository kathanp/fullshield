/**
 * Phase 264. Variants stay out of the default fixture set.
 * A transform that drops the sink is an engine gap, not a passing result.
 */
import { writeFileSync } from 'node:fs';

const TRANSFORMS = ['rename', 'helper', 'async', 'template', 'dead', 'barrel'];

export function variants(source, sinkCall) {
  return [
    ['rename', source.replaceAll('user', 'account')],
    ['helper', `function helper(v){ return v; }\n${source.replace(sinkCall, sinkCall.replace('(', '(helper('))}`],
    ['async', source.replace('function ', 'async function ')],
    ['template', source.replace('sql + x', '`${sql}${x}`')],
    ['dead', `${source}\nfunction unused(){ return 1; }\n`],
    ['barrel', `export { save } from './sink.js';\n${source}`],
  ];
}

function sinkSurvives(text, sinkCall) {
  return text.includes('db.query') && (text.includes(sinkCall) || text.includes('helper(') || text.includes('${x}'));
}

const invoked = process.argv[1]?.endsWith('metamorph.mjs') === true;
if (invoked) {
  const rule = process.argv[2] ?? 'SAST-SQLI-001';
  const out = process.argv[3];
  const source = 'function save(sql, x){ db.query(sql + x); }\n';
  const sinkCall = 'db.query(sql + x)';
  const failures = [];
  for (const [name, text] of variants(source, sinkCall)) {
    if (!sinkSurvives(text, sinkCall)) {failures.push({ rule, transform: name });}
  }
  const report = { rules: [rule], transforms: TRANSFORMS, failures };
  if (out !== undefined) {writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);}
  console.log(`gaps ${failures.length} rule ${rule}`);
}
