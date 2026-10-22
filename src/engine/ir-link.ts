import { AST_NODE_TYPES, type TSESTree } from '@typescript-eslint/typescript-estree';

import { applyPackageExports, applyTsPaths, packageSpec } from '../core/module-resolve.js';
import { literalString, propName, walk } from '../modules/sast/ast.js';
import { collectRequires } from '../modules/sast/interproc.js';
import type { ImportLink, IrResolveContext } from './ir-types.js';

/**
 * Record specifier → local binding.
 * Relative targets use `collectRequires` when the caller passes the project file set.
 * `applyTsPaths`, `packageSpec`, and `applyPackageExports` rewrite the specifier itself.
 * Barrel re-exports are not followed: that step lives inside `runInterproc` and is not exported.
 */
export function collectImportLinks(
  file: string,
  ast: TSESTree.Program,
  ctx?: IrResolveContext,
): ImportLink[] {
  const links: ImportLink[] = [];
  const add = (local: string, specifier: string, imported: string): void => {
    links.push(decorate(local, specifier, imported, ctx));
  };

  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.ImportDeclaration) {
      if (node.importKind === 'type') {return;}
      const specifier = literalString(node.source);
      if (specifier === undefined) {return;}
      if (node.specifiers.length === 0) {
        add(sideName(node), specifier, '*');
        return;
      }
      for (const spec of node.specifiers) {
        if (spec.type === AST_NODE_TYPES.ImportDefaultSpecifier) {
          add(spec.local.name, specifier, 'default');
        } else if (spec.type === AST_NODE_TYPES.ImportNamespaceSpecifier) {
          add(spec.local.name, specifier, '*');
        } else if (spec.importKind !== 'type') {
          add(spec.local.name, specifier, syntaxName(spec.imported) ?? 'default');
        }
      }
      return;
    }
    if (node.type === AST_NODE_TYPES.ExportAllDeclaration) {
      if (node.exportKind === 'type') {return;}
      const specifier = literalString(node.source);
      if (specifier === undefined) {return;}
      add(node.exported?.name ?? '*', specifier, '*');
      return;
    }
    if (node.type === AST_NODE_TYPES.ExportNamedDeclaration && node.source !== null) {
      if (node.exportKind === 'type') {return;}
      const specifier = literalString(node.source);
      if (specifier === undefined) {return;}
      for (const spec of node.specifiers) {
        if (spec.exportKind === 'type') {continue;}
        const exported = syntaxName(spec.exported);
        const local = syntaxName(spec.local);
        if (exported !== undefined && local !== undefined) {add(exported, specifier, local);}
      }
      return;
    }
    if (
      node.type === AST_NODE_TYPES.TSImportEqualsDeclaration &&
      node.importKind !== 'type' &&
      node.moduleReference.type === AST_NODE_TYPES.TSExternalModuleReference
    ) {
      const specifier = literalString(node.moduleReference.expression);
      if (specifier !== undefined) {add(node.id.name, specifier, '*');}
      return;
    }
    if (node.type === AST_NODE_TYPES.ImportExpression) {
      const specifier = literalString(node.source);
      if (specifier !== undefined) {add(sideName(node), specifier, '*');}
      return;
    }
    if (node.type === AST_NODE_TYPES.VariableDeclarator && node.init !== null) {
      const required = requireInfo(node.init);
      if (required === undefined) {return;}
      if (node.id.type === AST_NODE_TYPES.Identifier) {
        add(node.id.name, required.spec, required.exportName ?? '*');
        return;
      }
      if (node.id.type === AST_NODE_TYPES.ObjectPattern) {
        for (const prop of node.id.properties) {
          if (
            prop.type === AST_NODE_TYPES.Property &&
            prop.key.type === AST_NODE_TYPES.Identifier &&
            prop.value.type === AST_NODE_TYPES.Identifier
          ) {
            add(prop.value.name, required.spec, prop.key.name);
          }
        }
      }
    }
  });

  if (ctx?.files !== undefined) {
    const resolved = collectRequires(file, ast, ctx.files);
    for (const link of links) {
      const hit = resolved.get(link.local);
      if (hit !== undefined) {link.resolved = hit;}
    }
  }
  return links;
}

function decorate(local: string, specifier: string, imported: string, ctx?: IrResolveContext): ImportLink {
  const mapped = ctx?.tsPaths !== undefined ? applyTsPaths(specifier, ctx.tsPaths) : undefined;
  const pkg = packageSpec(specifier);
  let exportTarget: string | undefined;
  if (pkg !== undefined && ctx?.packageExports !== undefined) {
    exportTarget = applyPackageExports(pkg.subpath ?? '.', ctx.packageExports);
  }
  return {
    local,
    specifier,
    imported,
    ...(mapped !== undefined && mapped !== specifier ? { mappedSpecifier: mapped } : {}),
    ...(pkg !== undefined ? { packageName: pkg.packageName } : {}),
    ...(exportTarget !== undefined ? { exportTarget } : {}),
  };
}

function requireInfo(node: TSESTree.Node): { spec: string; exportName?: string } | undefined {
  if (node.type === AST_NODE_TYPES.CallExpression) {
    if (node.callee.type !== AST_NODE_TYPES.Identifier || node.callee.name !== 'require') {return undefined;}
    const arg = node.arguments[0];
    if (arg === undefined || arg.type === AST_NODE_TYPES.SpreadElement) {return undefined;}
    const spec = literalString(arg);
    return spec === undefined ? undefined : { spec };
  }
  if (node.type === AST_NODE_TYPES.MemberExpression && node.object.type === AST_NODE_TYPES.CallExpression) {
    const inner = requireInfo(node.object);
    const name = propName(node);
    if (inner === undefined || name === undefined) {return undefined;}
    return { spec: inner.spec, exportName: name };
  }
  return undefined;
}

function syntaxName(node: TSESTree.Identifier | TSESTree.StringLiteral): string | undefined {
  if (node.type === AST_NODE_TYPES.Identifier) {return node.name;}
  return typeof node.value === 'string' ? node.value : undefined;
}

function sideName(node: TSESTree.Node): string {
  const line = node.loc?.start.line ?? 0;
  const col = node.loc?.start.column ?? 0;
  return `<import:${line}:${col}>`;
}
