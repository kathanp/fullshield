/** Path and method only. `:id` and `[id]` compare as `{id}`. */
export function normPath(raw: string): string {
  let path = raw.trim();
  if (path === '') {return '/';}
  if (!path.startsWith('/')) {path = `/${path}`;}
  path = path.replace(/\/+/g, '/');
  if (path.length > 1 && path.endsWith('/')) {path = path.slice(0, -1);}
  path = path.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, '{$1}');
  path = path.replace(/\[([A-Za-z_][A-Za-z0-9_]*)\]/g, '{$1}');
  return path;
}

export function joinPath(prefix: string, path: string): string {
  if (prefix === '' || prefix === '/') {return normPath(path);}
  const left = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  const right = path.startsWith('/') ? path.slice(1) : path;
  return normPath(`${left}/${right}`);
}

export function nextFilePath(file: string): string | undefined {
  const name = file.split('\\').join('/');
  const match = /(?:^|\/)app\/(.*\/)?route\.[cm]?[jt]sx?$/.exec(name);
  if (match === null) {return undefined;}
  const parts = (match[1] ?? '').split('/').filter((part) => part !== '' && !/^\(.*\)$/.test(part));
  return normPath(`/${parts.join('/')}`);
}
