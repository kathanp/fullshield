import { register } from 'node:module';

import { enableRaspFromEnv } from './rasp/enable.js';

export { contextFromRequest, enterRaspContext } from './rasp/context.js';
export { RaspBlockedError } from './rasp/types.js';

enableRaspFromEnv();

try {
  register('./rasp/loader.js', import.meta.url);
} catch {
  // Fail open: CJS/builtin hooks are already installed when experimental.
}
