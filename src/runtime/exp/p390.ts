/**
 * Phase 390. Prototype writes.
 * Off unless FULLSHIELD_EXPERIMENTAL_PROTOFREEZE=1.
 * Freeze is opt-in and is not called at import time. The scanner process is not frozen.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PROTOFREEZE';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

const DANGEROUS = new Set(['__proto__', 'constructor', 'prototype']);

export interface ProtoFinding {
  ruleId: 'SAST-PROTO-001';
  key: string;
  message: string;
}

export function prototypeFinding(key: string, tainted: boolean, canBeDangerous: boolean): ProtoFinding | null {
  if (!enabled()) {
    return null;
  }
  if (DANGEROUS.has(key) || (tainted && canBeDangerous)) {
    return {
      ruleId: 'SAST-PROTO-001',
      key,
      message: `Key ${key} can write a prototype. Freeze of builtins is opt-in and can break the app.`,
    };
  }
  return null;
}

export interface BuiltinStandins {
  objectPrototype: object;
  arrayPrototype: object;
  functionPrototype: object;
}

/** Freezes the provided objects only when opt-in is true. Does not touch the real builtins unless they are passed in. */
export function freezeBuiltins(targets: BuiltinStandins, optIn: boolean): void {
  if (!enabled() || !optIn) {
    return;
  }
  Object.freeze(targets.objectPrototype);
  Object.freeze(targets.arrayPrototype);
  Object.freeze(targets.functionPrototype);
}
