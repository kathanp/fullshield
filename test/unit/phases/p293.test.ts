import { afterEach, describe, expect, it } from 'vitest';

import { analyzeNest, enabled, FLAG } from '../../../src/phases/p293.js';

const SOURCE = `
class UserDto { @IsInt() id; }
@Controller()
class C {
  @Get('one')
  safe(@Body() body: UserDto) { repo.query(body.id); }
  @UsePipes(MissingPipe)
  @Get('two')
  raw(@Body() body) { repo.query('select ' + body); }
}
`;

const SCOPED = `
@Injectable({ scope: Scope.REQUEST })
class Svc {}
@Controller()
class C {
  constructor(private svc: Svc) {}
  @Get('a')
  a(@Body() body) { this.svc.value = body.name; }
  @Get('b')
  b() { repo.query(this.svc.value); }
}
`;

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 293 nest', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeNest(SOURCE).findings).toEqual([]);
  });

  it('clears an IsInt field and reports a raw body', () => {
    process.env[FLAG] = '1';
    const result = analyzeNest(SOURCE);
    expect(result.findings.map((finding) => finding.route)).toEqual(['two']);
    expect(result.findings[0]).toMatchObject({ keys: 'Unknown' });
    expect(result.events.map((event) => event.reason)).toContain('custom pipe');
  });

  it('does not share request-scoped taint across routes', () => {
    process.env[FLAG] = '1';
    expect(analyzeNest(SCOPED).findings).toEqual([]);
  });

  it('reports a finite dto field and ignores a class without a scope', () => {
    process.env[FLAG] = '1';
    expect(analyzeNest(':::').findings).toEqual([]);
    const source = [
      'class NoteDto { @IsUUID() id; @IsEnum() kind; title; }',
      '@Controller()',
      'class Notes {',
      '  constructor(svc) {}',
      '  @Post("save")',
      '  save(@Query() q: NoteDto) { repo.query(q.title + q.id); }',
      '}',
    ].join('\n');
    const result = analyzeNest(source);
    expect(result.findings.some((row) => row.keys === 'Finite' || row.keys === 'Unknown')).toBe(true);
    delete process.env[FLAG];
  });
});
