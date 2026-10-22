import { afterEach, describe, expect, it } from 'vitest';

import { analyzeTemplates, enabled, FLAG } from '../../../src/phases/p306.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 306 templates', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeTemplates({ engine: 'ejs', files: { 'v.ejs': '<%- q %>' }, entry: 'v.ejs', taintedKeys: ['q'] }).findings).toEqual([]);
  });

  it('reports raw output and ignores an escaped text node', () => {
    process.env[FLAG] = '1';
    expect(analyzeTemplates({ engine: 'ejs', files: { 'v.ejs': '<%= q %>' }, entry: 'v.ejs', taintedKeys: ['q'] }).findings).toEqual([]);
    expect(analyzeTemplates({ engine: 'ejs', files: { 'v.ejs': '<%- q %>' }, entry: 'v.ejs', taintedKeys: ['q'] }).findings).toHaveLength(1);
    expect(analyzeTemplates({ engine: 'handlebars', files: { 'v.hbs': '{{q}}' }, entry: 'v.hbs', taintedKeys: ['q'] }).findings).toEqual([]);
    expect(analyzeTemplates({ engine: 'handlebars', files: { 'v.hbs': '{{{q}}}' }, entry: 'v.hbs', taintedKeys: ['q'] }).findings).toHaveLength(1);
    expect(analyzeTemplates({ engine: 'nunjucks', files: { 'v.njk': '{{ q }}' }, entry: 'v.njk', taintedKeys: ['q'] }).findings).toEqual([]);
    expect(analyzeTemplates({ engine: 'nunjucks', files: { 'v.njk': '{{ q | safe }}' }, entry: 'v.njk', taintedKeys: ['q'] }).findings).toHaveLength(1);
    expect(analyzeTemplates({ engine: 'pug', files: { 'v.pug': '= q' }, entry: 'v.pug', taintedKeys: ['q'] }).findings).toEqual([]);
    expect(analyzeTemplates({ engine: 'pug', files: { 'v.pug': '!= q' }, entry: 'v.pug', taintedKeys: ['q'] }).findings).toHaveLength(1);
    expect(analyzeTemplates({ engine: 'marko', files: { 'v.marko': '${q}' }, entry: 'v.marko', taintedKeys: ['q'] }).findings).toEqual([]);
    expect(analyzeTemplates({ engine: 'marko', files: { 'v.marko': '$!{q}' }, entry: 'v.marko', taintedKeys: ['q'] }).findings).toHaveLength(1);
  });

  it('includes both files for a raw partial and treats an unknown tag as raw', () => {
    process.env[FLAG] = '1';
    const partial = analyzeTemplates({
      engine: 'ejs',
      files: { 'view.ejs': "<%- include('part') %>", 'part.ejs': '<%- q %>' },
      entry: 'view.ejs',
      taintedKeys: ['q'],
    });
    expect(partial.findings[0]?.files).toEqual(['view.ejs', 'part.ejs']);
    const unknown = analyzeTemplates({ engine: 'ejs', files: { 'v.ejs': '<%: q %>' }, entry: 'v.ejs', taintedKeys: ['q'] });
    expect(unknown.events).toHaveLength(1);
    expect(unknown.findings).toHaveLength(1);
    const helper = analyzeTemplates({
      engine: 'handlebars',
      files: {
        'v.hbs': '{{safe q}}',
        'helpers.js': 'function safe(value) { return new Handlebars.SafeString(value); }',
      },
      entry: 'v.hbs',
      taintedKeys: ['q'],
    });
    expect(helper.findings).toHaveLength(1);
  });
});
