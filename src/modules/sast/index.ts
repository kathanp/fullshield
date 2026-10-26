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

async function withDeep(filename: string, source: string, findings: Finding[]): Promise<Finding[]> {
  if (process.env.FULLSHIELD_EXPERIMENTAL_DEEP !== '1') {return findings;}
  const { deepFindings } = await import('./deep.js');
  return [...findings, ...(await deepFindings(filename, source))];
}

async function experimentalOnText(filename: string, source: string, findings: Finding[]): Promise<Finding[]> {
  let next = findings;
  if (process.env.FULLSHIELD_EXPERIMENTAL_CRLF === '1') {
    const { crlfFindings } = await import('./crlf.js');
    next = [...next, ...(await crlfFindings(filename, source))];
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_MAIL === '1') {
    const { mailFindings } = await import('./mail.js');
    next = [...next, ...(await mailFindings(filename, source))];
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_FORMULA === '1') {
    const { formulaFindings } = await import('./formula.js');
    next = [...next, ...(await formulaFindings(filename, source))];
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_BROWSER === '1') {
    const { browserCtlFindings } = await import('./browserCtl.js');
    next = [...next, ...(await browserCtlFindings(filename, source))];
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_DYNIMPORT === '1') {
    const { dynimportFindings } = await import('./dynimport.js');
    next = [...next, ...(await dynimportFindings(filename, source))];
  }
  return next;
}

async function experimentalOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  const found: Finding[] = [];
  if (process.env.FULLSHIELD_EXPERIMENTAL_CRLF === '1') {
    const { crlfOnFiles } = await import('./crlf.js');
    found.push(...(await crlfOnFiles(cwd, files)));
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_MAIL === '1') {
    const { mailOnFiles } = await import('./mail.js');
    found.push(...(await mailOnFiles(cwd, files)));
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_FORMULA === '1') {
    const { formulaOnFiles } = await import('./formula.js');
    found.push(...(await formulaOnFiles(cwd, files)));
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_BROWSER === '1') {
    const { browserCtlOnFiles } = await import('./browserCtl.js');
    found.push(...(await browserCtlOnFiles(cwd, files)));
  }
  if (process.env.FULLSHIELD_EXPERIMENTAL_DYNIMPORT === '1') {
    const { dynimportOnFiles } = await import('./dynimport.js');
    found.push(...(await dynimportOnFiles(cwd, files)));
  }
  return found;
}

export const sastModule: ScanModule = {
  name: sastModuleInner.name,
  async run(ctx) {
    await syncFlow2();
    let findings = await sastModuleInner.run(ctx);
    if (process.env.FULLSHIELD_EXPERIMENTAL_LDAP === '1') {
      const { ldapOnFiles } = await import('./ldap.js');
      findings = [...findings, ...(await ldapOnFiles(ctx.cwd, ctx.files))];
    }
    findings = [...findings, ...(await experimentalOnFiles(ctx.cwd, ctx.files))];
    if (process.env.FULLSHIELD_EXPERIMENTAL_DEEP !== '1') {return findings;}
    const { deepOnFiles } = await import('./deep.js');
    return [...findings, ...(await deepOnFiles(ctx.cwd, ctx.files))];
  },
};

export async function runSastOnText(
  filename: string,
  source: string,
): ReturnType<typeof runSastText> {
  await syncFlow2();
  return experimentalOnText(
    filename,
    source,
    await withDeep(filename, source, await withLdap(filename, source, await runSastText(filename, source))),
  );
}

export { sastRules };
