import { afterEach, describe, expect, it } from 'vitest';

import { analyzeServerActions, enabled, FLAG } from '../../../src/phases/p295.js';

const FILES = {
  'app/actions.ts': "'use server';\nexport async function save(formData) { db.query('select ' + formData.get('body')); }\n",
  'app/page.tsx': "import { save } from './actions';\nexport default function Page() { return save; }\n",
  'app/other.tsx': 'export default function Other() { return null; }\n',
};

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 295 server actions', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeServerActions(FILES).findings).toEqual([]);
  });

  it('names the page and still reports concatenation behind auth', () => {
    process.env[FLAG] = '1';
    const open = analyzeServerActions(FILES);
    expect(open.findings[0]).toMatchObject({ injection: true, authState: 'absent', pages: ['app/page.tsx'] });
    const guarded = analyzeServerActions({
      ...FILES,
      'app/actions.ts': "'use server';\nexport async function save(formData) { requireAuth(); db.query('select ' + formData.get('body')); }\n",
    });
    expect(guarded.findings[0]).toMatchObject({ injection: true, authState: 'present' });
  });

  it('ignores a constant argument and a client that never calls the action', () => {
    process.env[FLAG] = '1';
    const result = analyzeServerActions({
      'app/actions.ts': "'use server';\nexport async function save(value) { db.query(value); }\n",
      'app/caller.tsx': "import { save } from './actions';\nsave('literal');\n",
      'app/other.tsx': 'export default function Other() { return null; }\n',
    });
    expect(result.findings).toEqual([]);
  });
});
