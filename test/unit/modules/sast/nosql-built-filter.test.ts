import { describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

async function nosql(code: string): Promise<number> {
  const hits = await runSastOnText('query.js', code);
  return hits.filter((finding) => finding.ruleId === 'SAST-NOSQLI-001').length;
}

describe('NoSQL filter built in a variable', () => {
  it('flags an object built from req.body and passed to find', async () => {
    const code = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const filter = { name: req.body.name };
        User.find(filter);
      }
    `;
    expect(await nosql(code)).toBeGreaterThan(0);
  });

  it('flags a property written onto the filter after it is created', async () => {
    const code = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const filter = {};
        filter.name = req.body.name;
        collection.find(filter);
      }
    `;
    expect(await nosql(code)).toBeGreaterThan(0);
  });

  it('flags Object.assign and a copy of that filter', async () => {
    const code = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const filter = Object.assign({}, { name: req.body.name });
        const copy = filter;
        User.find(copy);
      }
    `;
    expect(await nosql(code)).toBeGreaterThan(0);
  });

  it('does not flag a filter made only of literals', async () => {
    const code = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const filter = { name: 'ada' };
        User.find(filter);
      }
    `;
    expect(await nosql(code)).toBe(0);
  });

  it('flags a spread of req.body and an array of request ids', async () => {
    const spread = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const filter = { ...req.body };
        User.find(filter);
      }
    `;
    const list = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const ids = [req.body.id];
        User.find(ids);
      }
    `;
    expect(await nosql(spread)).toBeGreaterThan(0);
    expect(await nosql(list)).toBeGreaterThan(0);
  });

  it('does not flag a field wrapped in mongoSanitize', async () => {
    const code = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const name = mongoSanitize(req.body.name);
        const filter = { name };
        User.find(filter);
      }
    `;
    expect(await nosql(code)).toBe(0);
  });

  it('flags a filter returned from another function in the same file', async () => {
    const code = `
      const mongoose = require('mongoose');
      function build(req) {
        return { name: req.body.name };
      }
      function handler(req, res) {
        const filter = build(req);
        User.find(filter);
      }
    `;
    const direct = `
      const mongoose = require('mongoose');
      function build(req) {
        return { name: req.body.name };
      }
      function handler(req, res) {
        User.find(build(req));
      }
    `;
    const awaited = `
      const mongoose = require('mongoose');
      async function build(req) {
        return { name: req.body.name };
      }
      async function handler(req, res) {
        User.find(await build(req));
      }
    `;
    expect(await nosql(code)).toBeGreaterThan(0);
    expect(await nosql(direct)).toBeGreaterThan(0);
    expect(await nosql(awaited)).toBeGreaterThan(0);
  });

  it('flags a filter closed over by a nested function', async () => {
    const code = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const filter = { name: req.body.name };
        function inner() {
          User.find(filter);
        }
      }
    `;
    expect(await nosql(code)).toBeGreaterThan(0);
  });

  it('does not flag a nested function that builds a literal filter with the same name', async () => {
    const code = `
      const mongoose = require('mongoose');
      function handler(req, res) {
        const filter = { name: req.body.name };
        function inner() {
          const filter = { name: 'ada' };
          User.find(filter);
        }
      }
    `;
    expect(await nosql(code)).toBe(0);
  });

  it('does not flag a helper that returns a string or a literal object', async () => {
    const asString = `
      const mongoose = require('mongoose');
      function getName(req) {
        return req.body.name;
      }
      function handler(req, res) {
        User.find(getName(req));
      }
    `;
    const asLiteral = `
      const mongoose = require('mongoose');
      function build() {
        return { name: 'ada' };
      }
      function handler(req, res) {
        User.find(build());
      }
    `;
    expect(await nosql(asString)).toBe(0);
    expect(await nosql(asLiteral)).toBe(0);
  });

  it('does not treat a Sequelize file as Mongo', async () => {
    const code = `
      const { Sequelize } = require('sequelize');
      function handler(req, res) {
        const filter = { name: req.body.name };
        User.find(filter);
      }
    `;
    expect(await nosql(code)).toBe(0);
  });
});
