import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:http';
import { resolve, sep } from 'node:path';

import { confirmTarget, type Confirmation, type ConfirmRoute } from './index.js';

export async function confirmStartedApp(opts: {
  entry: string;
  cwd: string;
  routes: ConfirmRoute[];
  canaryToken?: string;
  timeoutMs?: number;
}): Promise<{ url: string; confirmations: Confirmation[] }> {
  const root = resolve(opts.cwd);
  const entry = resolve(root, opts.entry);
  if (entry !== root && !entry.startsWith(`${root}${sep}`)) {
    throw new Error('confirm: entry must stay inside the project');
  }
  const port = await freeLocalPort();
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, [entry], {
    cwd: root,
    env: { ...process.env, HOST: '127.0.0.1', PORT: String(port) },
    stdio: 'ignore',
  });
  try {
    await waitForLocal(url, opts.timeoutMs ?? 3000);
    const result = await confirmTarget(url, {
      experimental: true,
      routes: opts.routes,
      ...(opts.canaryToken !== undefined ? { canaryToken: opts.canaryToken } : {}),
    });
    return { url, confirmations: result.confirmations };
  } finally {
    await stopChild(child);
  }
}

function freeLocalPort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      server.close((err) => (err ? reject(err) : resolvePort(port)));
    });
  });
}

async function waitForLocal(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(200) });
      await res.text();
      return;
    } catch {
      await new Promise((resolveWait) => { setTimeout(resolveWait, 40); });
    }
  }
  throw new Error(`confirm: app did not listen on ${url}`);
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {return;}
  child.kill('SIGTERM');
  await new Promise<void>((resolveStop) => {
    const timer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) {child.kill('SIGKILL');}
    }, 500);
    child.once('exit', () => {
      clearTimeout(timer);
      resolveStop();
    });
  });
}
