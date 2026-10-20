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
