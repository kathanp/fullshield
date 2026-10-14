import { makeFindingId, type Finding } from '../../core/finding.js';

const CDN_HEADERS = ['cf-ray', 'x-amz-cf-id', 'x-served-by', 'x-cache', 'x-akamai-request-id'];
const CDN_SERVER = /cloudflare|akamai|fastly|cloudfront|sucuri|incapsula/i;

const PROBES = ['/.env', '/.git/HEAD', '/package.json', '/debug', '/server-status'];

export interface EdgeOptions {
  url: string;
  fetchImpl?: typeof fetch;
  delayMs?: number;
}

function finding(
  ruleId: string,
  title: string,
  severity: Finding['severity'],
  message: string,
  file?: string,
): Finding {
  return {
    id: makeFindingId(ruleId, file ?? 'edge', message),
    ruleId,
    module: 'config',
    title,
    severity,
    confidence: 'medium',
    file,
    message,
    remediation: title,
    references: [ruleId],
  };
}

function headerMap(headers: Headers): Map<string, string> {
  const out = new Map<string, string>();
  headers.forEach((value, key) => out.set(key.toLowerCase(), value));
  return out;
}

function hasCdn(headers: Map<string, string>): boolean {
  if (CDN_HEADERS.some((h) => headers.has(h))) return true;
  const server = headers.get('server') ?? '';
  return CDN_SERVER.test(server);
}

async function pause(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, ms));
}

/** Live-URL posture check. GET/HEAD only, only the URL the caller passed. */
export async function runEdge(options: EdgeOptions): Promise<Finding[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const delayMs = options.delayMs ?? 1000;
  const target = new URL(options.url);
  const findings: Finding[] = [];

  const home = await fetchImpl(target, { method: 'GET', redirect: 'manual' });
  await home.text().catch(() => undefined);
  const headers = headerMap(home.headers);

  if (!hasCdn(headers)) {
    findings.push(
      finding('EDGE-CDN-001', 'No DDoS/WAF layer detected', 'high', 'No DDoS/WAF layer detected.'),
    );
  }

  if (target.protocol === 'http:') {
    const loc = headers.get('location') ?? '';
    const redirected = home.status >= 300 && home.status < 400 && loc.startsWith('https:');
    if (!redirected) {
      findings.push(
        finding(
          'EDGE-TLS-001',
          'HTTP without HTTPS redirect',
          'medium',
          'Site is served over HTTP and does not redirect to HTTPS.',
        ),
      );
    }
  }

  const required: Array<[string, string, string]> = [
    ['strict-transport-security', 'EDGE-HSTS-001', 'Missing Strict-Transport-Security'],
    ['content-security-policy', 'EDGE-CSP-001', 'Missing Content-Security-Policy'],
    ['x-content-type-options', 'EDGE-XCTO-001', 'Missing X-Content-Type-Options'],
    ['x-frame-options', 'EDGE-XFO-001', 'Missing X-Frame-Options (or CSP frame-ancestors)'],
    ['referrer-policy', 'EDGE-REFERRER-001', 'Missing Referrer-Policy'],
  ];
  const csp = headers.get('content-security-policy') ?? '';
  for (const [header, ruleId, title] of required) {
    if (header === 'x-frame-options' && /frame-ancestors/i.test(csp)) continue;
    if (!headers.has(header)) {
      findings.push(finding(ruleId, title, 'medium', `${title}.`));
    }
  }

  for (const path of PROBES) {
    await pause(delayMs);
    const probe = new URL(path, target);
    const res = await fetchImpl(probe, { method: 'GET', redirect: 'manual' });
    if (res.status === 200) {
      const body = (await res.text()).slice(0, 80);
      if (body.trim().length > 0) {
        findings.push(
          finding(
            'EDGE-EXPOSE-001',
            `Exposed path ${path}`,
            'high',
            `${path} returned HTTP 200.`,
            path,
          ),
        );
      }
    }
  }

  return findings;
}
