import { afterEach, describe, expect, it } from 'vitest';

import { analyzeQueue, enabled, FLAG } from '../../../src/phases/p302.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 302 queues', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeQueue("worker.process('jobs', (job) => { exec(job.data); });").findings).toEqual([]);
  });

  it('promotes only the matching literal queue', () => {
    process.env[FLAG] = '1';
    const linked = analyzeQueue("queue.add('jobs', req.body);\nworker.process('jobs', (job) => { exec(job.data); });");
    expect(linked.findings[0]).toMatchObject({ origins: ['request', 'queue'], confidence: 'high', queue: 'jobs' });
    const other = analyzeQueue("queue.add('jobs', req.body);\nworker.process('other', (job) => { exec(job.data); });");
    expect(other.findings[0]).toMatchObject({ origins: ['queue'], confidence: 'medium', queue: 'other' });
    const bound = analyzeQueue("worker.process('jobs', (job) => { db.query('select ?', [job.data]); });");
    expect(bound.findings).toEqual([]);
  });

  it('links a member payload and ignores a handler that never reaches exec', () => {
    process.env[FLAG] = '1';
    const result = analyzeQueue(`
      queue.add('jobs', req.body.user);
      queue.add('jobs', payload.user);
      queue.add('jobs', 1);
      queue.add('jobs', ...items);
      queue.add(name, req.body);
      worker.process('jobs', (job) => { exec(job.data); db.query('select ?', [job.id]); db.query('select ?', ...job); query('select ?', job); db.query(job); db.query('select 1', job); db.query('select $1', job); db.query('select ?'); });
      worker.process('other', (job) => { cp.exec(job.name); });
      worker.process('plain', function (job) { exec('fixed'); });
      worker.process(name, (job) => { exec(job); });
      worker.process('bad', handler);
      worker.process('missing');
      worker.process('arr', (job) => { exec([job, ...rest]); exec('x' + job); });
    `, { file: 'q.js' });
    expect(result.findings.find((finding) => finding.queue === 'jobs')).toMatchObject({ file: 'q.js', origins: ['request', 'queue'], confidence: 'high' });
    expect(result.findings.find((finding) => finding.queue === 'arr')).toMatchObject({ origins: ['queue'], confidence: 'medium' });
    expect(result.findings.find((finding) => finding.queue === 'other')).toBeUndefined();
    expect(result.findings.find((finding) => finding.queue === 'plain')).toBeUndefined();
    expect(analyzeQueue('???').findings).toEqual([]);
  });
});
