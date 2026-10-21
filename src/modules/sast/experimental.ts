/** Phase 96 crypto v2. Off unless FULLSHIELD_EXPERIMENTAL_CRYPTO2=1. */
export function crypto2Enabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_CRYPTO2 === '1';
}

/** Phase 102 Electron window settings. Off unless FULLSHIELD_EXPERIMENTAL_ELECTRON=1. */
export function electronEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_ELECTRON === '1';
}

/** Phase 104 vendored JS. Off unless FULLSHIELD_EXPERIMENTAL_VENDORED=1. */
export function vendoredEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_VENDORED === '1';
}

/** Phase 97 server-side template injection. Off unless FULLSHIELD_EXPERIMENTAL_SSTI=1. */
export function sstiEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_SSTI === '1';
}

/** Phase 99 webhook verifiers. Off unless FULLSHIELD_EXPERIMENTAL_WEBHOOK=1. */
export function webhookEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_WEBHOOK === '1';
}

/** Phase 100 session fixation. Off unless FULLSHIELD_EXPERIMENTAL_SESSION2=1. */
export function session2Enabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_SESSION2 === '1';
}

/** Phase 98 secret logging. Off unless FULLSHIELD_EXPERIMENTAL_LOGLEAK=1. */
export function logLeakEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_LOGLEAK === '1';
}

/** Phase 103 Next.js boundary. Off unless FULLSHIELD_EXPERIMENTAL_NEXT=1. */
export function nextEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_NEXT === '1';
}

/** Phase 101 browser JS. Off unless FULLSHIELD_EXPERIMENTAL_BROWSER=1. */
export function browserEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_BROWSER === '1';
}

/** Phase 106 unfixed dependencies. Off unless FULLSHIELD_EXPERIMENTAL_HEALTH=1. */
export function healthEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_HEALTH === '1';
}

/** Phase 107 IDOR hints. Off unless FULLSHIELD_EXPERIMENTAL_IDOR=1. */
export function idorEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_IDOR === '1';
}

/** Phase 95 disabled TLS verification. Off unless FULLSHIELD_EXPERIMENTAL_TLS=1. */
export function tlsEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_TLS === '1';
}

/** Phase 27 extra SAST sinks. Off unless the env flag or CLI option is set. */
export function sastGapsEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_SAST_GAPS === '1';
}

/** Phase 28 Next/Nest/Hono/Koa taint + AUTH. Off unless the env flag or CLI option is set. */
export function frameworksEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_FRAMEWORKS === '1';
}

/** Phase 29 extra vuln classes. Off unless the env flag or CLI option is set. */
export function classesEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_CLASSES === '1';
}

/** Phase 33 MCP config/taint. Off unless FULLSHIELD_EXPERIMENTAL_MCPCFG=1. */
export function mcpCfgEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_MCPCFG === '1';
}

/** Phase 81 library model packs. Off unless FULLSHIELD_EXPERIMENTAL_MODELS=1. */
export const MODELS_FLAG = 'FULLSHIELD_EXPERIMENTAL_MODELS';

export function modelsEnabled(): boolean {
  return process.env[MODELS_FLAG] === '1';
}

/** Phase 40 extra taint propagation. Off unless FULLSHIELD_EXPERIMENTAL_TAINT_V2=1. */
export function taintV2Enabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_TAINT_V2 === '1';
}

/** Phase 80 receiver types. Off unless FULLSHIELD_EXPERIMENTAL_TYPES=1. */
export const TYPES_FLAG = 'FULLSHIELD_EXPERIMENTAL_TYPES';

export function typesEnabled(): boolean {
  return process.env[TYPES_FLAG] === '1';
}

/** GitHub annotations, JUnit, and GitLab Code Quality. Off unless this is `1`. */
export const CI_REPORTS_FLAG = 'FULLSHIELD_EXPERIMENTAL_CI_REPORTS';

export function ciReportsEnabled(): boolean {
  return process.env[CI_REPORTS_FLAG] === '1';
}

/** Compare two scan JSON files. Off unless this is `1`. */
export const DIFF_FLAG = 'FULLSHIELD_EXPERIMENTAL_DIFF';

/** GPL/AGPL notices from installed package.json files. Off unless this is `1`. */
export const LICENSE_FLAG = 'FULLSHIELD_EXPERIMENTAL_LICENSE';

export function licenseEnabled(): boolean {
  return process.env[LICENSE_FLAG] === '1';
}

export function diffEnabled(): boolean {
  return process.env[DIFF_FLAG] === '1';
}
