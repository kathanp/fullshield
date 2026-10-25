import type { Finding } from '../../core/finding.js';
import type { ScanModule } from '../../core/engine.js';
import { runSastOnText as runSastText, sastModule as sastModuleInner, sastRules } from './engine.js';

async function syncFlow2(): Promise<void> {
  const { installFlow2 } = await import('./flow2.js');
  installFlow2();
}

async function withLdap(filename: string, source: string, findings: Finding[]): Promise<Finding[]> {
  if (process.env.FULLSHIELD_EXPERIMENTAL_LDAP !== '1') {return findings;}
  const { ldapFindings } = await import('./ldap.js');
  return [...findings, ...(await ldapFindings(filename, source))];
}

export const sastModule: ScanModule = {
  name: sastModuleInner.name,
  async run(ctx) {
    await syncFlow2();
    const findings = await sastModuleInner.run(ctx);
    if (process.env.FULLSHIELD_EXPERIMENTAL_LDAP !== '1') {return findings;}
    const { ldapOnFiles } = await import('./ldap.js');
    return [...findings, ...(await ldapOnFiles(ctx.cwd, ctx.files))];
  },
};

export async function runSastOnText(
  filename: string,
  source: string,
): ReturnType<typeof runSastText> {
  await syncFlow2();
  return withLdap(filename, source, await runSastText(filename, source));
}

export { sastRules };
