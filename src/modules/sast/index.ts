import { runSastOnText as runSastText, sastModule as sastModuleInner, sastRules } from './engine.js';
import { setFlow2Active, setFlow2Seed } from './taint.js';
import type { ScanModule } from '../../core/engine.js';

async function syncFlow2(): Promise<void> {
  if (process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 === '1') {
    const { installFlow2 } = await import('./flow2.js');
    installFlow2();
    return;
  }
  setFlow2Active(false);
  setFlow2Seed(undefined);
}

export const sastModule: ScanModule = {
  name: sastModuleInner.name,
  async run(ctx) {
    await syncFlow2();
    return sastModuleInner.run(ctx);
  },
};

export async function runSastOnText(
  filename: string,
  source: string,
): ReturnType<typeof runSastText> {
  await syncFlow2();
  return runSastText(filename, source);
}

export { sastRules };
