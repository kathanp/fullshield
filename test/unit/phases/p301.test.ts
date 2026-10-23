import { afterEach, describe, expect, it } from 'vitest';

import { analyzeServerless, enabled, FLAG } from '../../../src/phases/p301.js';

const MANIFEST = `
functions:
  httpJob:
    handler: index.handler
    events:
      - http:
          path: /items
          method: get
  cronJob:
    handler: index.cron
    events:
      - schedule: rate(1 day)
`;

const SOURCE = `
export async function handler(event) { exec(event.body); }
export async function cron(event) { exec(event.body); }
export async function fetch(request, env) { fetch(env.API_HOST); }
`;

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 301 serverless', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeServerless(SOURCE, MANIFEST).findings).toEqual([]);
  });

  it('treats http and cron differently and ignores a worker env fetch', () => {
    process.env[FLAG] = '1';
    const result = analyzeServerless(SOURCE, MANIFEST);
    const http = result.findings.find((finding) => finding.route === 'handler');
    const cron = result.findings.find((finding) => finding.route === 'cron');
    expect(http).toMatchObject({ origin: 'request', severity: 'high', trigger: 'http' });
    expect(cron).toMatchObject({ origin: 'event', severity: 'medium', trigger: 'cron' });
    expect(result.findings.find((finding) => finding.route === 'fetch')).toBeUndefined();
  });

  it('does not upgrade a bad manifest or a missing export', () => {
    process.env[FLAG] = '1';
    const unknown = analyzeServerless('export async function handler(event) { exec(event.body); }', null);
    expect(unknown.findings[0]).toMatchObject({ origin: 'event', trigger: 'unknown' });
    const broken = analyzeServerless('export async function handler(event) { exec(event.body); }', ':::');
    expect(broken.events).toHaveLength(1);
    expect(broken.findings[0]?.origin).toBe('event');
    const missing = analyzeServerless('export async function handler(event) { exec(event.body); }', 'functions:\n  job:\n    handler: index.missing\n    events:\n      - http:\n          path: /x\n          method: get\n');
    expect(missing.routes).toEqual([]);
  });

  it('reads HttpApi and Schedule resources and an exported default handler', () => {
    process.env[FLAG] = '1';
    const source = `
      function handler(event) { child.exec(event.body); execSync(event.queryStringParameters.q); fetch(); }
      export default { worker(event) { fetch(env.HOST); exec(env.TOKEN); } };
      export function plain(event) { execSync(event.url); }
      export function other(event) { fetch(event.body); }
    `;
    const manifest = `
Resources:
  Http:
    Type: HttpApi
    Handler: index.handler
    Properties:
      Path: /items
  Cron:
    Type: Schedule
    Handler: index.plain
`;
    const result = analyzeServerless(source, manifest, { file: 'fn.js' });
    expect(result.findings.find((finding) => finding.route === 'handler')).toMatchObject({ file: 'fn.js', origin: 'request', severity: 'high', trigger: 'http' });
    expect(result.findings.find((finding) => finding.route === 'plain')).toMatchObject({ origin: 'event', severity: 'medium', trigger: 'cron' });
    expect(result.findings.find((finding) => finding.route === 'worker')).toBeUndefined();
    expect(result.routes).toEqual(['/items', 'plain']);
    expect(analyzeServerless('???', manifest).findings).toEqual([]);
    expect(analyzeServerless(source, ' \n ').findings[0]?.trigger).toBe('unknown');
  });

  it('accepts an empty yaml value and rejects a list that is not a map', () => {
    process.env[FLAG] = '1';
    const quiet = analyzeServerless('function handler(event) { exec(event.body); }', 'root:\n  empty:\nlist:\n  - plain\n  - name: value\n  - bare:\n');
    expect(quiet.events).toEqual([]);
    expect(quiet.findings).toEqual([]);
    const broken = analyzeServerless('function handler(event) { exec(event.body); }', 'list:\n  - name:\n      notakey\n');
    expect(broken.events).toHaveLength(1);
    expect(analyzeServerless('function handler(event) { exec(event.body); }', 'hello\n').events).toHaveLength(1);
    expect(analyzeServerless('function handler(event) { exec(event.body); }', '\tfoo: bar\n').events).toHaveLength(1);
  });
});
