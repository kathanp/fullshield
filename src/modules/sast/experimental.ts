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
