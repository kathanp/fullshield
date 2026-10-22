import { afterEach, describe, expect, it } from 'vitest';

import { analyzeOrm, enabled, FLAG } from '../../../src/phases/p299.js';
import { resetVersionCache } from '../../../src/phases/p310.js';

afterEach(() => {
  delete process.env[FLAG];
  delete process.env.FULLSHIELD_EXPERIMENTAL_VERKEY;
  resetVersionCache();
});

describe('phase 299 orm', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeOrm("sequelize.query(req.query.q);", { library: 'sequelize', version: '6.0.0' }).findings).toEqual([]);
  });

  it('reports raw and whole-object filters and skips a bound placeholder', () => {
    process.env[FLAG] = '1';
    const sequelize = analyzeOrm("sequelize.query(req.query.q); User.findAll({ where: req.body }); User.findAll({ where: { id: req.params.id } }); qb.where('id = ?', id);", { library: 'sequelize', version: '6.37.0', packagePath: 'nm/sequelize' });
    expect(sequelize.findings.map((finding) => finding.sink)).toEqual(['raw', 'operator']);
    const mongoose = analyzeOrm('Model.find({ $where: req.query.q });', { library: 'mongoose', version: '8.0.0', packagePath: 'nm/mongoose' });
    expect(mongoose.findings.map((finding) => finding.sink)).toEqual(['raw']);
    const drizzle = analyzeOrm('db.execute(sql.raw(req.query.q));', { library: 'drizzle', version: '0.29.1', packagePath: 'nm/drizzle' });
    expect(drizzle.findings).toHaveLength(1);
    const typeorm = analyzeOrm("repo.query(req.query.q); qb.where('id = ?', id);", { library: 'typeorm', version: '0.3.20', packagePath: 'nm/typeorm' });
    expect(typeorm.findings.map((finding) => finding.sink)).toEqual(['raw']);
  });

  it('falls back on an unsupported major without a bound-parameter finding', () => {
    process.env[FLAG] = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_VERKEY = '1';
    const result = analyzeOrm("sequelize.query(req.query.q); qb.where('id = ?', id);", { library: 'sequelize', version: '5.0.0', packagePath: 'nm/sequelize5' });
    expect(result.row).toBeNull();
    expect(result.events.map((event) => event.reason)).toContain('version-gap');
    expect(result.findings.map((finding) => finding.sink)).toEqual(['raw']);
  });
});
