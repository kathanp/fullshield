/**
 * Phase 337. Dockerfile build arguments.
 * Off unless FULLSHIELD_EXPERIMENTAL_DOCKERARG=1.
 * Does not run a build. An unconnected stage graph treats the ARG as reaching the final stage.
 */

import { matchGrammar, type SecretFormat } from './p332.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DOCKERARG';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface DockerFinding {
  ruleId: 'SECRETS-DOCKER-001';
  severity: 'info' | 'high';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export interface DockerResult {
  findings: DockerFinding[];
  events: { code: 271; file: string; detail: string }[];
}

interface Stage {
  name: string;
  args: { name: string; value: string; line: number }[];
  copiedFrom: string[];
  echoes: string[];
  incomplete: boolean;
}

function openStage(line: string, count: number): Stage | undefined {
  const from = /^FROM\s+\S+(?:\s+AS\s+(\S+))?/i.exec(line);
  if (from === null) {
    return undefined;
  }
  return { name: from[1] ?? `stage-${String(count)}`, args: [], copiedFrom: [], echoes: [], incomplete: false };
}

function pushNamed(stage: Stage, match: RegExpExecArray | null, lineNo: number): boolean {
  if (match?.[1] === undefined) {
    return false;
  }
  stage.args.push({ name: match[1], value: match[2] ?? '', line: lineNo });
  return true;
}

function pushAssignment(stage: Stage, line: string, lineNo: number): boolean {
  if (pushNamed(stage, /^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?/.exec(line), lineNo)) {
    return true;
  }
  return pushNamed(stage, /^ENV\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?/.exec(line), lineNo);
}

function noteCopy(stage: Stage, line: string, stages: readonly Stage[]): void {
  if (line.includes('--mount=type=secret')) {
    return;
  }
  const copy = /COPY\s+--from=(\S+)/i.exec(line);
  if (copy?.[1] !== undefined) {
    stage.copiedFrom.push(copy[1]);
    if (!stages.some((item) => item.name === copy[1])) {
      stage.incomplete = true;
    }
  }
  const echoed = /RUN\s+echo\s+\$([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
  if (echoed?.[1] !== undefined) {
    stage.echoes.push(echoed[1]);
  }
}

function parseStages(text: string): Stage[] {
  const stages: Stage[] = [];
  let current: Stage | undefined;
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    const opened = openStage(line, stages.length);
    if (opened !== undefined) {
      current = opened;
      stages.push(current);
      continue;
    }
    if (current === undefined || pushAssignment(current, line, index + 1)) {
      continue;
    }
    noteCopy(current, line, stages);
  }
  return stages;
}

function secretMountOnly(text: string): boolean {
  return text.includes('--mount=type=secret') && !/^(?:ARG|ENV)\s+/m.test(text);
}

function reachableNames(stages: readonly Stage[], root: string, file: string, events: DockerResult['events']): Set<string> {
  const stack = [root];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const name = stack.pop();
    if (name === undefined || seen.has(name)) {
      continue;
    }
    seen.add(name);
    const stage = stages.find((item) => item.name === name);
    if (stage === undefined) {
      events.push({ code: 271, file, detail: 'stage graph incomplete' });
      continue;
    }
    for (const from of stage.copiedFrom) {
      stack.push(from);
    }
  }
  return seen;
}

function addNames(reached: Set<string>, stage: Stage): void {
  for (const arg of stage.args) {
    reached.add(arg.name);
  }
}

function reachedArgs(stages: readonly Stage[], file: string, events: DockerResult['events']): Set<string> {
  const reached = new Set<string>();
  const finalStage = stages[stages.length - 1];
  if (finalStage === undefined) {
    return reached;
  }
  const seen = reachableNames(stages, finalStage.name, file, events);
  for (const stage of stages) {
    if (seen.has(stage.name) || stage.incomplete) {
      addNames(reached, stage);
    }
  }
  if (!stages.some((stage) => stage.incomplete)) {
    return reached;
  }
  events.push({ code: 271, file, detail: 'stage graph incomplete' });
  for (const stage of stages) {
    addNames(reached, stage);
  }
  return reached;
}

function argWitness(echoed: boolean, high: boolean): string {
  if (echoed) {
    return 'echo';
  }
  if (high) {
    return 'final';
  }
  return 'intermediate';
}

interface ArgContext {
  reached: ReadonlySet<string>;
  finalStage: Stage | undefined;
  file: string;
  formats: readonly SecretFormat[];
}

function argFinding(stage: Stage, arg: Stage['args'][number], ctx: ArgContext): DockerFinding | undefined {
  if (matchGrammar(arg.value, ctx.formats) === undefined) {
    return undefined;
  }
  const echoed = stage.echoes.includes(arg.name);
  const forwarded = ctx.reached.has(arg.name) && stage !== ctx.finalStage;
  const high = echoed || forwarded || stage === ctx.finalStage;
  const severity = high ? 'high' : 'info';
  const message = high ? `ARG ${arg.name} reaches the final image or a log sink.` : `ARG ${arg.name} dies with an intermediate stage.`;
  return { ruleId: 'SECRETS-DOCKER-001', severity, file: ctx.file, line: arg.line, message, witness: argWitness(echoed, high) };
}

export function dockerFindings(file: string, text: string, formats: readonly SecretFormat[]): DockerResult {
  if (!enabled() || secretMountOnly(text)) {
    return { findings: [], events: [] };
  }
  const stages = parseStages(text);
  const events: DockerResult['events'] = [];
  const ctx: ArgContext = { reached: reachedArgs(stages, file, events), finalStage: stages[stages.length - 1], file, formats };
  const findings: DockerFinding[] = [];
  for (const stage of stages) {
    for (const arg of stage.args) {
      const hit = argFinding(stage, arg, ctx);
      if (hit !== undefined) {
        findings.push(hit);
      }
    }
  }
  return { findings, events };
}
