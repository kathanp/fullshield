export {
  IMPLEMENTED_MODULES,
  builtinModules,
  runScan,
  scan,
} from './core/engine.js';
export type {
  ModuleContext,
  ScanMetadata,
  ScanModule,
  ScanOptions,
  ScanResult,
} from './core/engine.js';

export { CONFIG_FILE_NAME, ConfigError, DEFAULT_CONFIG, loadConfig } from './core/config.js';
export type { DepsConfig, NotifyConfig, ResolvedConfig } from './core/config.js';

export {
  MODULE_NAMES,
  SEVERITIES,
  isModuleName,
  isSeverity,
  makeFindingId,
  meetsThreshold,
  severityRank,
  sortFindings,
  summarize,
} from './core/finding.js';
export type {
  Confidence,
  Finding,
  FindingSummary,
  FixProposal,
  ModuleName,
  Severity,
} from './core/finding.js';

export { walkFiles } from './core/fileWalker.js';
export type { WalkOptions } from './core/fileWalker.js';

export { packageVersion } from './core/version.js';
export { renderConsoleReport } from './reporters/console.js';
export { renderJsonReport } from './reporters/json.js';
