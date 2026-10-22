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
});
