import { makeFindingId, type Finding, type FindingSource, type ModuleName, type Severity, findingSource } from '../core/finding.js';

const REACH = new Set<string>([
  'reachable',
  'imported-not-called',
  'reachable-via-dependency',
  'not-imported',
  'reachability-unknown',
  'symbol-reachable',
  'symbol-not-called',
]);

const ROUTE = new Set<Finding['routeExposure']>(['unauthenticated', 'authenticated', 'unknown']);

export interface IngestItem {
  finding: Finding;
  fingerprints: string[];
}

export interface ItemInput {
  ruleId: string;
  externalRuleIds: string[];
  module: ModuleName;
  title: string;
  severity: Severity;
  externalSeverity: string;
  message: string;
  source: FindingSource | string;
  file?: string;
  line?: number;
  cwe?: string;
  snippet?: string;
  fingerprints?: string[];
  reachability?: Finding['reachability'];
  sinkClass?: string;
  routeExposure?: Finding['routeExposure'];
}

export function makeItem(input: ItemInput): IngestItem {
  const ids = [...new Set(input.externalRuleIds)].sort();
  const ruleId = input.ruleId;
  const finding: Finding = {
    id: makeFindingId(ruleId, input.file, input.snippet ?? input.message),
    ruleId,
    module: input.module,
    title: input.title,
    severity: input.severity,
    confidence: 'medium',
    message: input.message,
    remediation: 'Review the original tool report. FullShield did not rescore this finding.',
    source: findingSource(input.source),
    sources: [input.source],
    externalRuleId: ids.find((id) => id !== ruleId) ?? ids[0] ?? ruleId,
    externalRuleIds: ids.length > 0 ? ids : [ruleId],
    externalSeverity: input.externalSeverity,
  };
  if (input.cwe !== undefined) {finding.cwe = input.cwe;}
  if (input.file !== undefined) {finding.file = input.file;}
  if (input.line !== undefined) {finding.line = input.line;}
  if (input.snippet !== undefined) {finding.snippet = input.snippet;}
  if (input.reachability !== undefined) {finding.reachability = input.reachability;}
  if (input.sinkClass !== undefined) {finding.sinkClass = input.sinkClass;}
  if (input.routeExposure !== undefined) {finding.routeExposure = input.routeExposure;}
  return { finding, fingerprints: input.fingerprints ?? [] };
}

export function evidenceOf(props: Record<string, unknown> | undefined): Pick<
  Finding,
  'reachability' | 'sinkClass' | 'routeExposure'
> {
  if (props === undefined) {return {};}
  const out: Pick<Finding, 'reachability' | 'sinkClass' | 'routeExposure'> = {};
  const reach = props.reachability;
  if (typeof reach === 'string' && REACH.has(reach)) {out.reachability = reach as Finding['reachability'];}
  const sink = typeof props.sinkClass === 'string' ? props.sinkClass : props['sink-class'];
  if (typeof sink === 'string' && sink.length > 0) {out.sinkClass = sink;}
  const route = routeOf(props);
  if (route !== undefined) {out.routeExposure = route;}
  return out;
}

function routeOf(props: Record<string, unknown>): Finding['routeExposure'] | undefined {
  const direct = props.routeExposure ?? props['route-exposure'];
  if (typeof direct === 'string' && ROUTE.has(direct as Finding['routeExposure'])) {
    return direct as Finding['routeExposure'];
  }
  const auth = props.auth;
  if (auth === 'present' || auth === 'authenticated') {return 'authenticated';}
  if (auth === 'missing' || auth === 'absent' || auth === 'unauthenticated') {return 'unauthenticated';}
  return undefined;
}
