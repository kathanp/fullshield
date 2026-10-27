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

async function appendFlag(
  flag: string,
  findings: Finding[],
  load: () => Promise<Finding[]>,
): Promise<Finding[]> {
  if (process.env[flag] !== '1') {return findings;}
  return [...findings, ...(await load())];
}

async function experimentalOnText(filename: string, source: string, findings: Finding[]): Promise<Finding[]> {
  let next = findings;
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_CRLF', next, async () => (await import('./crlf.js')).crlfFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_MAIL', next, async () => (await import('./mail.js')).mailFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_FORMULA', next, async () => (await import('./formula.js')).formulaFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_BROWSER', next, async () => (await import('./browserCtl.js')).browserCtlFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_DYNIMPORT', next, async () => (await import('./dynimport.js')).dynimportFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_REDIS', next, async () => (await import('./redis.js')).redisFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_XPATH', next, async () => (await import('./xpath.js')).xpathFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_SEARCH', next, async () => (await import('./search.js')).searchFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_OBJECTKEY', next, async () => (await import('./objectkey.js')).objectkeyFindings(filename, source));
  next = await appendFlag('FULLSHIELD_EXPERIMENTAL_WORKER', next, async () => (await import('./worker.js')).workerFindings(filename, source));
  return next;
}

async function experimentalOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  let found: Finding[] = [];
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_CRLF', found, async () => (await import('./crlf.js')).crlfOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_MAIL', found, async () => (await import('./mail.js')).mailOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_FORMULA', found, async () => (await import('./formula.js')).formulaOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_BROWSER', found, async () => (await import('./browserCtl.js')).browserCtlOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_DYNIMPORT', found, async () => (await import('./dynimport.js')).dynimportOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_REDIS', found, async () => (await import('./redis.js')).redisOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_XPATH', found, async () => (await import('./xpath.js')).xpathOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_SEARCH', found, async () => (await import('./search.js')).searchOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_OBJECTKEY', found, async () => (await import('./objectkey.js')).objectkeyOnFiles(cwd, files));
  found = await appendFlag('FULLSHIELD_EXPERIMENTAL_WORKER', found, async () => (await import('./worker.js')).workerOnFiles(cwd, files));
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
