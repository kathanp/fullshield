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

function parseStages(text: string): Stage[] {
  const stages: Stage[] = [];
  let current: Stage | undefined;
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    const from = /^FROM\s+\S+(?:\s+AS\s+(\S+))?/i.exec(line);
    if (from !== null) {
      current = { name: from[1] ?? `stage-${String(stages.length)}`, args: [], copiedFrom: [], echoes: [], incomplete: false };
      stages.push(current);
      continue;
    }
    if (current === undefined) {
      continue;
    }
    const arg = /^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?/.exec(line);
    if (arg?.[1] !== undefined) {
      current.args.push({ name: arg[1], value: arg[2] ?? '', line: index + 1 });
      continue;
    }
    const env = /^ENV\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?/.exec(line);
    if (env?.[1] !== undefined) {
      current.args.push({ name: env[1], value: env[2] ?? '', line: index + 1 });
      continue;
    }
    if (line.includes('--mount=type=secret')) {
      continue;
    }
    const copy = /COPY\s+--from=(\S+)/i.exec(line);
    if (copy?.[1] !== undefined) {
      current.copiedFrom.push(copy[1]);
      if (!stages.some((stage) => stage.name === copy[1])) {
        current.incomplete = true;
      }
    }
    const echoed = /RUN\s+echo\s+\$([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
    if (echoed?.[1] !== undefined) {
      current.echoes.push(echoed[1]);
    }
  }
  return stages;
}

export function dockerFindings(file: string, text: string, formats: readonly SecretFormat[]): DockerResult {
  if (!enabled()) {
    return { findings: [], events: [] };
  }
  if (text.includes('--mount=type=secret') && !/^(?:ARG|ENV)\s+/m.test(text)) {
    return { findings: [], events: [] };
  }
  const stages = parseStages(text);
  const finalStage = stages[stages.length - 1];
  const findings: DockerFinding[] = [];
  const events: DockerResult['events'] = [];
  const reached = new Set<string>();
  if (finalStage !== undefined) {
    const stack = [finalStage.name];
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
    for (const stage of stages) {
      if (seen.has(stage.name) || stage.incomplete) {
        for (const arg of stage.args) {
          reached.add(arg.name);
        }
      }
    }
    if (stages.some((stage) => stage.incomplete)) {
      events.push({ code: 271, file, detail: 'stage graph incomplete' });
      for (const stage of stages) {
        for (const arg of stage.args) {
          reached.add(arg.name);
        }
      }
    }
  }
  for (const stage of stages) {
    for (const arg of stage.args) {
      if (matchGrammar(arg.value, formats) === undefined) {
        continue;
      }
      const echoed = stage.echoes.includes(arg.name);
      const forwarded = reached.has(arg.name) && stage !== finalStage;
      const high = echoed || forwarded || stage === finalStage;
      findings.push({
        ruleId: 'SECRETS-DOCKER-001',
        severity: high ? 'high' : 'info',
        file,
        line: arg.line,
        message: high ? `ARG ${arg.name} reaches the final image or a log sink.` : `ARG ${arg.name} dies with an intermediate stage.`,
        witness: echoed ? 'echo' : high ? 'final' : 'intermediate',
      });
    }
  }
  return { findings, events };
}
