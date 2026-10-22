/**
 * Phase 438. Hook templates.
 * Off unless FULLSHIELD_EXPERIMENTAL_HOOKTPL=1.
 * Flag off: init text is returned unchanged.
 * Templates are text. They do not download a hook tool or edit git config.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HOOKTPL';
export const PRECOMMIT_COMMAND = 'npx fullshield precommit';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type HookKind = 'husky' | 'lefthook' | 'pre-commit';

const HUSKY = `#!/bin/sh
# not the full scan
${PRECOMMIT_COMMAND}
`;

const LEFTHOOK = `pre-commit:
  commands:
    fullshield:
      run: ${PRECOMMIT_COMMAND}
`;

const PRE_COMMIT = `repos:
  - repo: local
    hooks:
      - id: fullshield
        name: fullshield
        entry: ${PRECOMMIT_COMMAND}
        language: system
`;

const TEMPLATES: Record<HookKind, string> = {
  husky: HUSKY,
  lefthook: LEFTHOOK,
  'pre-commit': PRE_COMMIT,
};

export function renderHook(kind: HookKind): string | null {
  if (!enabled()) {
    return null;
  }
  return TEMPLATES[kind];
}

export function initOutput(existing: string): string {
  if (!enabled()) {
    return existing;
  }
  return `${existing}\n${HUSKY}`;
}
