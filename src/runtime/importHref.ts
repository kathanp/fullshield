import { pathToFileURL } from 'node:url';

/** `file://` href for `node --import`. Bare absolute paths break on Windows. */
export function importHref(filePath: string): string {
  return pathToFileURL(filePath).href;
}
