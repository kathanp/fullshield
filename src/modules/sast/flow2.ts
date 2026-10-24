import { isFunctionNode, walk } from './ast.js';
import { flow2LocalTaintOf, setFlow2Active, setFlow2Seed } from './taint.js';
import type { AstNode } from './types.js';

function enclosingFunction(node: AstNode): AstNode | undefined {
  let parent: AstNode | undefined = (node as { parent?: AstNode }).parent;
  while (parent !== undefined) {
    if (isFunctionNode(parent)) {return parent;}
    parent = (parent as { parent?: AstNode }).parent;
  }
  return undefined;
}

function parentFunction(fn: AstNode): AstNode | undefined {
  let parent: AstNode | undefined = (fn as { parent?: AstNode }).parent;
  while (parent !== undefined) {
    if (isFunctionNode(parent)) {return parent;}
    parent = (parent as { parent?: AstNode }).parent;
  }
  return undefined;
}

function declaredNames(fn: AstNode): Set<string> {
  const names = new Set<string>();
  if (!isFunctionNode(fn)) {return names;}
  for (const param of fn.params) {
    if (param.type === 'Identifier') {names.add(param.name);}
  }
  walk(fn, (node) => {
    if (node !== fn && enclosingFunction(node) !== fn) {return;}
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {names.add(node.id.name);}
    if (node.type === 'FunctionDeclaration' && node !== fn && node.id !== null) {names.add(node.id.name);}
  });
  return names;
}

function shadowed(declared: ReadonlySet<string>, key: string): boolean {
  if (declared.has(key)) {return true;}
  const dot = key.indexOf('.');
  return dot > 0 && declared.has(key.slice(0, dot));
}

/** One function boundary. Copies names born in the parent, not names the parent only received as a seed. */
export function installFlow2(): void {
  setFlow2Active(true);
  setFlow2Seed((functions, seeds) => {
    let changed = false;
    for (const fn of functions) {
      const parent = parentFunction(fn);
      if (parent === undefined) {continue;}
      const declared = declaredNames(fn);
      const set = seeds.get(fn) ?? new Set<string>();
      for (const name of flow2LocalTaintOf(parent)) {
        if (shadowed(declared, name) || set.has(name)) {continue;}
        set.add(name);
        seeds.set(fn, set);
        changed = true;
      }
    }
    return changed;
  });
}
