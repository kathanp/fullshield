export {
  IMPLEMENTED_MODULES,
  builtinModules,
  runScan,
  scan,
} from './core/engine.js';
export type {
  ModuleContext,
  PolicyScanResult,
  ScanMetadata,
  ScanModule,
  ScanOptions,
  ScanResult,
} from './core/engine.js';

export { CONFIG_FILE_NAME, ConfigError, DEFAULT_CONFIG, loadConfig } from './core/config.js';
export type { AiConfig, DepsConfig, NotifyConfig, ResolvedConfig } from './core/config.js';

export {
  MODULE_NAMES,
  SEVERITIES,
  isModuleName,
  isSeverity,
  makeFindingId,
  failsCi,
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
export { runFix } from './fixer/index.js';
export type { FixOptions, FixPatch, FixResult } from './fixer/index.js';
export { createAiClient, isInternalAi, isLiveAi } from './ai/provider.js';
export { scanTextForSecrets } from './modules/secrets/index.js';
export { runAiFix } from './ai/fixLoop.js';
export { applyBaseline, readBaseline, writeBaseline } from './core/baseline.js';
export type { BaselineFile } from './core/baseline.js';
export {
  POLICY_FILE_NAME,
  POLICY_FLAG,
  POLICY_PEER_ERROR,
  PolicyError,
  applyPolicy,
  isPolicyEnabled,
  loadPolicy,
  parsePolicy,
  renderPrSummary,
  ruleDocsUrl,
} from './policy/index.js';
export type { AppliedPolicy, FullShieldPolicy, PolicyException } from './policy/index.js';
export { applyInlineSuppressions, parseIgnore } from './core/suppression.js';
export { renderConsoleReport } from './reporters/console.js';
export { renderHtmlReport } from './reporters/html.js';
export { renderJsonReport } from './reporters/json.js';
export { renderMarkdownReport } from './reporters/markdown.js';
export { renderSarifReport, validateSarif21 } from './reporters/sarif.js';
export { buildSbom } from './sbom/index.js';
export { renderCycloneDx, validateCycloneDx15 } from './sbom/cyclonedx.js';
export type { SbomComponent, SbomInput } from './sbom/cyclonedx.js';
