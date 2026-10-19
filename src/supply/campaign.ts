import { makeFindingId, type Finding } from '../core/finding.js';

const RPC_RE = /getSignaturesForAddress|eth_getLogs/;
const NET_RE = /https\.request|http\.request|fetch\s*\(|axios\./;
const EVAL_RE = /\beval\s*\(/;
const STEAL_RE = /Login Data|leveldb|discord[\\/]Local Storage|wallet-extension|Ethereum\/keystore/i;
const PLATFORM_RE = /process\.platform\s*===\s*['"]win32['"]|os\.platform\s*\(\s*\)/;
const DOWNLOAD_RE = /https?:\/\/example\.invalid|createWriteStream|https\.get/;
const SPAWN_RE = /child_process|spawn\s*\(|execFile\s*\(|\.exe['"]/;

function hit(ruleId: string, title: string, message: string, file: string | undefined, severity: Finding['severity']): Finding {
  return {
    id: makeFindingId(ruleId, file, message),
    ruleId,
    module: 'deps',
    title,
    severity,
    confidence: 'high',
    file,
    message,
    remediation: 'Do not install this package. Remove it, delete node_modules, and reinstall from a clean lockfile.',
  };
}

/** Static combinations only. A single signal is not a finding. */
export function campaignFindings(files: readonly { file: string; text: string }[]): Finding[] {
  const findings: Finding[] = [];
  for (const source of files) {
    const hasChain = RPC_RE.test(source.text);
    const hasNet = NET_RE.test(source.text) || EVAL_RE.test(source.text);
    if (hasChain && hasNet) {
      findings.push(
        hit(
          'SUPPLY-CHAINC2-001',
          'Package reads a blockchain RPC and then fetches or evaluates the result',
          'static: RPC method combined with fetch or eval',
          source.file,
          'high',
        ),
      );
    }
    const steals = STEAL_RE.test(source.text);
    const callsNet = NET_RE.test(source.text);
    if (steals && callsNet) {
      findings.push(
        hit(
          'SUPPLY-STEALER-001',
          'Package reads a local credential store and makes a network call',
          'static: browser, chat, or wallet path combined with a network call',
          source.file,
          'critical',
        ),
      );
    }
    const gated = PLATFORM_RE.test(source.text);
    const downloads = DOWNLOAD_RE.test(source.text);
    const spawns = SPAWN_RE.test(source.text);
    if (gated && downloads && spawns) {
      findings.push(
        hit(
          'SUPPLY-PLATFORMGATE-001',
          'Package downloads and launches a file only on one platform',
          'static: platform check combined with a download and a process spawn',
          source.file,
          'high',
        ),
      );
    }
  }
  return findings;
}

export function securityPlaceholderFinding(name: string, locked: string, latest: string | undefined): Finding | undefined {
  if (latest !== '0.0.1-security') return undefined;
  if (locked === '0.0.1-security') return undefined;
  return hit(
    'SUPPLY-SECHOLDER-001',
    `Locked ${name}@${locked} was replaced on the registry by the security placeholder`,
    `${name} latest is 0.0.1-security while the lockfile pins ${locked}`,
    'package-lock.json',
    'critical',
  );
}
