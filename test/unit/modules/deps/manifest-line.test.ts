import { describe, expect, it } from 'vitest';

import { lineOfManifestDep } from '../../../../src/modules/deps/pins.js';

describe('phase 26c — attribute deps to package.json line', () => {
  it('returns the line of a direct dependency name', () => {
    const raw = `{\n  "name": "app",\n  "dependencies": {\n    "marked": "0.3.5",\n    "st": "0.2.4"\n  }\n}\n`;
    expect(lineOfManifestDep(raw, 'marked')).toBe(4);
    expect(lineOfManifestDep(raw, 'st')).toBe(5);
  });

  it('returns undefined for a name that is not a dependency', () => {
    const raw = `{\n  "name": "app",\n  "dependencies": {\n    "express": "4.18.2"\n  }\n}\n`;
    expect(lineOfManifestDep(raw, 'marked')).toBeUndefined();
    expect(lineOfManifestDep(raw, 'name')).toBeUndefined();
  });
});
