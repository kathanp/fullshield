import { AST_NODE_TYPES, type TSESTree } from '@typescript-eslint/typescript-estree';

import { boundNames, propName } from '../modules/sast/ast.js';
import { collectImportLinks } from './ir-link.js';
import type { FunctionIr, IrNode, IrParam, IrResolveContext, ModuleIr } from './ir-types.js';

type FnNode = TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression;

type Enqueue = (node: FnNode, hint: string | undefined) => void;

const BOOLEAN_BIN = new Set(['==', '===', '!=', '!==', '<', '<=', '>', '>=', 'in', 'instanceof']);

const SKIP_STMT = new Set<string>([
  AST_NODE_TYPES.BreakStatement,
  AST_NODE_TYPES.ContinueStatement,
  AST_NODE_TYPES.EmptyStatement,
  AST_NODE_TYPES.DebuggerStatement,
  AST_NODE_TYPES.ImportDeclaration,
  AST_NODE_TYPES.ExportAllDeclaration,
  AST_NODE_TYPES.TSTypeAliasDeclaration,
  AST_NODE_TYPES.TSInterfaceDeclaration,
  AST_NODE_TYPES.TSDeclareFunction,
  AST_NODE_TYPES.TSEnumDeclaration,
  AST_NODE_TYPES.TSModuleDeclaration,
]);

/**
 * Intra-procedural SSA. Nested functions are separate and do not capture the parent env.
 * `switch` arms are joined as alternatives; fallthrough is not modeled.
 * Loops merge the pre-loop env with the body once (may-analysis, not a fixpoint).
 */
export function lowerAst(file: string, ast: TSESTree.Program, ctx?: IrResolveContext): ModuleIr {
  const imports = collectImportLinks(file, ast, ctx);
  const functions: FunctionIr[] = [];
  const queue: Array<{ node: FnNode; name: string }> = [];
  const used = new Map<string, number>();

  const enqueue: Enqueue = (node, hint) => {
    const base = hint !== undefined && hint.length > 0 ? hint : '<anonymous>';
    const seen = used.get(base) ?? 0;
    used.set(base, seen + 1);
    const name = hint !== undefined && hint.length > 0 && seen === 0 ? hint : `${base}#${seen + 1}`;
    queue.push({ node, name });
  };

  const moduleLowerer = new Lowerer(file, enqueue);
  for (const stmt of ast.body) {
    moduleLowerer.statement(stmt);
  }
  functions.push(moduleLowerer.finish('<module>', ast.loc?.start.line ?? 1, ast.loc?.start.column ?? 0));

  for (let index = 0; index < queue.length; index += 1) {
    const item = queue[index];
    if (item === undefined) {continue;}
    const lowerer = new Lowerer(file, enqueue);
    lowerer.lowerFunction(item.node);
    functions.push(lowerer.finish(
      item.name,
      item.node.loc?.start.line ?? 0,
      item.node.loc?.start.column ?? 0,
    ));
  }
  return { file, imports, functions };
}

class Lowerer {
  private readonly nodes: IrNode[] = [];
  private readonly params: IrParam[] = [];
  private env = new Map<string, number>();
  private next = 1;

  constructor(
    private readonly file: string,
    private readonly enqueue: Enqueue,
  ) {}

  finish(name: string, line: number, col: number): FunctionIr {
    return { name, file: this.file, line, col, params: this.params, nodes: this.nodes };
  }

  lowerFunction(fn: FnNode): void {
    for (const param of fn.params) {
      this.defineParam(param);
    }
    if (fn.body === null || fn.body === undefined) {return;}
    if (fn.body.type === AST_NODE_TYPES.BlockStatement) {
      this.statement(fn.body);
      return;
    }
    const value = this.lowerExpr(fn.body);
    this.nodes.push({ op: 'return', ...this.loc(fn.body), args: [value] });
  }

  statement(node: TSESTree.Node): void {
    if (SKIP_STMT.has(node.type)) {return;}
    if (this.statementFlow(node)) {return;}
    this.statementDecl(node);
  }

  private statementFlow(node: TSESTree.Node): boolean {
    if (node.type === AST_NODE_TYPES.BlockStatement) {
      for (const stmt of node.body) {this.statement(stmt);}
      return true;
    }
    if (node.type === AST_NODE_TYPES.ExpressionStatement) {
      this.lowerExpr(node.expression);
      return true;
    }
    if (node.type === AST_NODE_TYPES.IfStatement) {
      this.lowerIf(node);
      return true;
    }
    if (node.type === AST_NODE_TYPES.WhileStatement) {
      this.lowerLoop(node.test, () => { this.statement(node.body); }, node);
      return true;
    }
    if (node.type === AST_NODE_TYPES.DoWhileStatement) {
      this.lowerDo(node);
      return true;
    }
    if (node.type === AST_NODE_TYPES.ForStatement) {
      this.lowerFor(node);
      return true;
    }
    if (node.type === AST_NODE_TYPES.ForInStatement || node.type === AST_NODE_TYPES.ForOfStatement) {
      this.lowerForInOf(node);
      return true;
    }
    if (node.type === AST_NODE_TYPES.SwitchStatement) {
      this.lowerSwitch(node);
      return true;
    }
    if (node.type === AST_NODE_TYPES.TryStatement) {
      this.lowerTry(node);
      return true;
    }
    if (node.type === AST_NODE_TYPES.ThrowStatement) {
      this.lowerExpr(node.argument);
      return true;
    }
    if (node.type === AST_NODE_TYPES.LabeledStatement) {
      this.statement(node.body);
      return true;
    }
    if (node.type === AST_NODE_TYPES.WithStatement) {
      this.lowerExpr(node.object);
      this.statement(node.body);
      return true;
    }
    return false;
  }

  private statementDecl(node: TSESTree.Node): void {
    if (node.type === AST_NODE_TYPES.VariableDeclaration) {
      this.lowerVariable(node);
      return;
    }
    if (node.type === AST_NODE_TYPES.FunctionDeclaration) {
      this.lowerFunctionDecl(node);
      return;
    }
    if (node.type === AST_NODE_TYPES.ClassDeclaration) {
      this.lowerClass(node);
      return;
    }
    if (node.type === AST_NODE_TYPES.ReturnStatement) {
      this.lowerReturn(node);
      return;
    }
    if (node.type === AST_NODE_TYPES.ExportDefaultDeclaration) {
      this.lowerExportDefault(node);
      return;
    }
    if (node.type === AST_NODE_TYPES.ExportNamedDeclaration) {
      this.lowerExportNamed(node);
      return;
    }
    if (node.type === AST_NODE_TYPES.TSImportEqualsDeclaration) {
      this.defineOne(node.id.name, undefined, node.id);
    }
  }

  private lowerFunctionDecl(node: TSESTree.FunctionDeclaration): void {
    this.enqueue(node, node.id?.name);
    if (node.id !== null) {this.defineOne(node.id.name, undefined, node.id);}
  }

  private lowerReturn(node: TSESTree.ReturnStatement): void {
    if (node.argument === null) {
      this.nodes.push({ op: 'return', ...this.loc(node) });
      return;
    }
    const value = this.lowerExpr(node.argument);
    this.nodes.push({ op: 'return', ...this.loc(node), args: [value] });
  }

  private lowerExportNamed(node: TSESTree.ExportNamedDeclaration): void {
    if (node.declaration !== null) {this.statement(node.declaration);}
  }

  private lowerExpr(node: TSESTree.Node, hint?: string): number {
    const current = this.unwrap(node);
    const primary = this.lowerPrimaryExpr(current);
    if (primary !== undefined) {return primary;}
    return this.lowerSecondaryExpr(current, hint);
  }

  private lowerPrimaryExpr(current: TSESTree.Node): number | undefined {
    if (current.type === AST_NODE_TYPES.Identifier) {
      return this.env.get(current.name) ?? this.freeName(current.name, current);
    }
    if (current.type === AST_NODE_TYPES.Literal || current.type === AST_NODE_TYPES.TemplateLiteral) {
      return this.lowerLiteralLike(current);
    }
    if (current.type === AST_NODE_TYPES.MemberExpression) {return this.lowerMember(current);}
    if (current.type === AST_NODE_TYPES.CallExpression || current.type === AST_NODE_TYPES.NewExpression) {
      return this.lowerCall(current);
    }
    if (current.type === AST_NODE_TYPES.AwaitExpression) {return this.lowerAwait(current);}
    if (current.type === AST_NODE_TYPES.AssignmentExpression) {return this.lowerAssignment(current);}
    if (current.type === AST_NODE_TYPES.BinaryExpression) {return this.lowerBinary(current);}
    if (current.type === AST_NODE_TYPES.LogicalExpression) {return this.lowerLogical(current);}
    if (current.type === AST_NODE_TYPES.ConditionalExpression) {return this.lowerConditional(current);}
    if (current.type === AST_NODE_TYPES.UnaryExpression) {return this.lowerUnary(current);}
    return undefined;
  }

  private lowerSecondaryExpr(current: TSESTree.Node, hint?: string): number {
    const named = this.lowerNamedExpr(current);
    if (named !== undefined) {return named;}
    if (current.type === AST_NODE_TYPES.UpdateExpression) {return this.lowerUpdate(current);}
    if (current.type === AST_NODE_TYPES.ObjectExpression) {return this.lowerObject(current);}
    if (current.type === AST_NODE_TYPES.ArrayExpression) {return this.lowerArray(current);}
    if (current.type === AST_NODE_TYPES.FunctionExpression || current.type === AST_NODE_TYPES.ArrowFunctionExpression) {
      return this.lowerFnExpr(current, hint);
    }
    if (current.type === AST_NODE_TYPES.ClassExpression) {return this.lowerClass(current, hint);}
    if (current.type === AST_NODE_TYPES.SequenceExpression) {return this.lowerSequence(current);}
    if (current.type === AST_NODE_TYPES.TaggedTemplateExpression) {return this.lowerTagged(current);}
    if (current.type === AST_NODE_TYPES.ImportExpression) {return this.lowerImportExpr(current);}
    if (current.type === AST_NODE_TYPES.YieldExpression) {return this.lowerYield(current);}
    return this.unknown(current);
  }

  private lowerNamedExpr(current: TSESTree.Node): number | undefined {
    if (current.type === AST_NODE_TYPES.MetaProperty) {
      return this.freeName(`${current.meta.name}.${current.property.name}`, current);
    }
    if (current.type === AST_NODE_TYPES.ThisExpression) {
      return this.env.get('this') ?? this.freeName('this', current);
    }
    if (current.type === AST_NODE_TYPES.Super) {
      return this.env.get('super') ?? this.freeName('super', current);
    }
    return undefined;
  }

  private lowerAwait(current: TSESTree.AwaitExpression): number {
    const inner = this.lowerExpr(current.argument);
    const dest = this.fresh();
    this.nodes.push({ op: 'await', ...this.loc(current), dest, args: [inner] });
    return dest;
  }

  private lowerLogical(current: TSESTree.LogicalExpression): number {
    const left = this.lowerExpr(current.left);
    const right = this.lowerExpr(current.right);
    return this.copy(current, [left, right]);
  }

  private lowerFnExpr(
    current: TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
    hint?: string,
  ): number {
    const hintName = current.type === AST_NODE_TYPES.FunctionExpression && current.id !== null ? current.id.name : hint;
    this.enqueue(current, hintName);
    return this.freeValue(current, hintName);
  }

  private lowerSequence(current: TSESTree.SequenceExpression): number {
    if (current.expressions.length === 0) {return this.unknown(current);}
    let last = 0;
    for (const expr of current.expressions) {last = this.lowerExpr(expr);}
    return last;
  }

  private lowerImportExpr(current: TSESTree.ImportExpression): number {
    const arg = this.lowerExpr(current.source);
    const dest = this.fresh();
    this.nodes.push({ op: 'call', ...this.loc(current), dest, name: 'import', args: [arg] });
    return dest;
  }

  private lowerYield(current: TSESTree.YieldExpression): number {
    if (current.argument === null) {return this.unknown(current);}
    return this.copy(current, [this.lowerExpr(current.argument)]);
  }

  private lowerVariable(node: TSESTree.VariableDeclaration): void {
    for (const decl of node.declarations) {
      const literal = decl.init === null ? undefined : this.pureLiteral(decl.init);
      if (decl.id.type === AST_NODE_TYPES.Identifier && literal !== undefined) {
        this.defineLiteral(decl.id.name, literal, decl.id);
        continue;
      }
      const hint = decl.id.type === AST_NODE_TYPES.Identifier ? decl.id.name : undefined;
      const source = decl.init === null ? undefined : this.lowerExpr(decl.init, hint);
      this.defineNames(decl.id, source, decl.id);
    }
  }

  private lowerIf(node: TSESTree.IfStatement): void {
    const cond = this.lowerExpr(node.test);
    this.nodes.push({ op: 'branch', ...this.loc(node), cond });
    const before = this.snapshot();
    this.env = new Map(before);
    this.statement(node.consequent);
    const thenEnv = this.snapshot();
    this.env = new Map(before);
    if (node.alternate !== null) {this.statement(node.alternate);}
    const elseEnv = this.snapshot();
    this.env = this.mergeTwo(before, thenEnv, elseEnv, node);
  }

  private lowerDo(node: TSESTree.DoWhileStatement): void {
    const before = this.snapshot();
    this.statement(node.body);
    const cond = this.lowerExpr(node.test);
    this.nodes.push({ op: 'branch', ...this.loc(node), cond });
    const after = this.snapshot();
    this.env = this.mergeTwo(before, before, after, node);
  }

  private lowerFor(node: TSESTree.ForStatement): void {
    if (node.init !== null) {
      if (node.init.type === AST_NODE_TYPES.VariableDeclaration) {this.statement(node.init);}
      else {this.lowerExpr(node.init);}
    }
    this.lowerLoop(node.test, () => {
      this.statement(node.body);
      if (node.update !== null) {this.lowerExpr(node.update);}
    }, node);
  }

  private lowerLoop(test: TSESTree.Expression | null, body: () => void, locNode: TSESTree.Node): void {
    const before = this.snapshot();
    if (test !== null) {
      const cond = this.lowerExpr(test);
      this.nodes.push({ op: 'branch', ...this.loc(locNode), cond });
    }
    body();
    const after = this.snapshot();
    this.env = this.mergeTwo(before, before, after, locNode);
  }

  private lowerForInOf(node: TSESTree.ForInStatement | TSESTree.ForOfStatement): void {
    const right = this.lowerExpr(node.right);
    let source = right;
    if (node.type === AST_NODE_TYPES.ForOfStatement && node.await) {
      const dest = this.fresh();
      this.nodes.push({ op: 'await', ...this.loc(node), dest, args: [right] });
      source = dest;
    }
    const before = this.snapshot();
    this.nodes.push({ op: 'branch', ...this.loc(node), cond: source });
    this.bindLoopLeft(node.left, source);
    this.statement(node.body);
    const after = this.snapshot();
    this.env = this.mergeTwo(before, before, after, node);
  }

  private lowerSwitch(node: TSESTree.SwitchStatement): void {
    const before = this.snapshot();
    const disc = this.lowerExpr(node.discriminant);
    this.nodes.push({ op: 'branch', ...this.loc(node), cond: disc });
    const arms: Array<Map<string, number>> = [];
    let hasDefault = false;
    for (const item of node.cases) {
      if (item.test === null) {hasDefault = true;}
      this.env = new Map(before);
      if (item.test !== null) {this.lowerExpr(item.test);}
      for (const stmt of item.consequent) {this.statement(stmt);}
      arms.push(this.snapshot());
    }
    if (arms.length === 0) {
      this.env = before;
      return;
    }
    let acc = arms[0] ?? before;
    for (let index = 1; index < arms.length; index += 1) {
      const arm = arms[index];
      if (arm === undefined) {continue;}
      acc = this.mergeTwo(before, acc, arm, node);
    }
    if (!hasDefault) {acc = this.mergeTwo(before, acc, before, node);}
    this.env = acc;
  }

  private lowerTry(node: TSESTree.TryStatement): void {
    const before = this.snapshot();
    this.statement(node.block);
    const afterTry = this.snapshot();
    this.env = new Map(before);
    if (node.handler !== null) {
      if (node.handler.param !== null) {this.defineNames(node.handler.param, undefined, node.handler.param);}
      this.statement(node.handler.body);
    }
    const afterCatch = this.snapshot();
    this.env = node.handler === null
      ? this.mergeTwo(before, afterTry, before, node)
      : this.mergeTwo(before, afterTry, afterCatch, node);
    if (node.finalizer !== null) {this.statement(node.finalizer);}
  }

  private lowerConditional(node: TSESTree.ConditionalExpression): number {
    const cond = this.lowerExpr(node.test);
    this.nodes.push({ op: 'branch', ...this.loc(node), cond });
    const before = this.snapshot();
    const thenId = this.lowerExpr(node.consequent);
    const thenEnv = this.snapshot();
    this.env = new Map(before);
    const elseId = this.lowerExpr(node.alternate);
    const elseEnv = this.snapshot();
    this.env = this.mergeTwo(before, thenEnv, elseEnv, node);
    if (thenId === elseId) {return thenId;}
    const dest = this.fresh();
    this.nodes.push({ op: 'phi', ...this.loc(node), dest, args: [thenId, elseId] });
    return dest;
  }

  private lowerAssignment(node: TSESTree.AssignmentExpression): number {
    if (node.operator === '=' && node.left.type === AST_NODE_TYPES.Identifier) {
      const literal = this.pureLiteral(node.right);
      if (literal !== undefined) {return this.defineLiteral(node.left.name, literal, node.left);}
      return this.defineOne(node.left.name, this.lowerExpr(node.right), node.left);
    }
    if (node.operator === '=' && node.left.type === AST_NODE_TYPES.MemberExpression) {
      const obj = this.lowerExpr(node.left.object);
      const ref = this.memberRef(node.left);
      const value = this.lowerExpr(node.right);
      this.nodes.push({
        op: 'property-store',
        ...this.loc(node),
        name: ref.name,
        args: ref.propId === undefined ? [obj, value] : [obj, value, ref.propId],
      });
      return value;
    }
    if (node.operator === '=') {
      const value = this.lowerExpr(node.right);
      this.defineNames(node.left, value, node.left);
      return value;
    }
    const leftId = this.lowerExpr(node.left);
    const rightId = this.lowerExpr(node.right);
    const dest = this.copy(node, [leftId, rightId]);
    if (node.left.type === AST_NODE_TYPES.Identifier) {this.env.set(node.left.name, dest);}
    return dest;
  }

  private lowerCall(node: TSESTree.CallExpression | TSESTree.NewExpression): number {
    let name: string | undefined;
    let objectId: number | undefined;
    const callee = node.callee;
    if (callee.type === AST_NODE_TYPES.Identifier) {
      objectId = this.lowerExpr(callee);
      name = callee.name;
    } else if (callee.type === AST_NODE_TYPES.MemberExpression) {
      objectId = this.lowerExpr(callee.object);
      name = this.memberRef(callee).name;
    } else {
      objectId = this.lowerExpr(callee);
    }
    const args: number[] = [];
    for (const arg of node.arguments) {
      args.push(arg.type === AST_NODE_TYPES.SpreadElement ? this.lowerExpr(arg.argument) : this.lowerExpr(arg));
    }
    const dest = this.fresh();
    this.nodes.push({
      op: 'call',
      ...this.loc(node),
      dest,
      ...(name !== undefined ? { name } : {}),
      ...(objectId !== undefined ? { object: objectId } : {}),
      ...(args.length > 0 ? { args } : {}),
    });
    return dest;
  }

  private lowerMember(node: TSESTree.MemberExpression): number {
    const obj = this.lowerExpr(node.object);
    const ref = this.memberRef(node);
    const dest = this.fresh();
    this.nodes.push({
      op: 'property-load',
      ...this.loc(node),
      dest,
      name: ref.name,
      args: ref.propId === undefined ? [obj] : [obj, ref.propId],
    });
    return dest;
  }

  private lowerBinary(node: TSESTree.BinaryExpression): number {
    const left = this.lowerExpr(node.left);
    const right = this.lowerExpr(node.right);
    if (BOOLEAN_BIN.has(node.operator)) {return this.unknown(node);}
    return this.copy(node, [left, right]);
  }

  private lowerUnary(node: TSESTree.UnaryExpression): number {
    const arg = this.lowerExpr(node.argument);
    if (node.operator === '!' || node.operator === 'typeof' || node.operator === 'void' || node.operator === 'delete') {
      return this.unknown(node);
    }
    return this.copy(node, [arg]);
  }

  private lowerUpdate(node: TSESTree.UpdateExpression): number {
    const prev = this.lowerExpr(node.argument);
    const dest = this.copy(node, [prev]);
    if (node.argument.type === AST_NODE_TYPES.Identifier) {this.env.set(node.argument.name, dest);}
    return node.prefix ? dest : prev;
  }

  private lowerObject(node: TSESTree.ObjectExpression): number {
    const dest = this.fresh();
    this.nodes.push({ op: 'assign', ...this.loc(node), dest });
    for (const prop of node.properties) {
      if (prop.type === AST_NODE_TYPES.SpreadElement) {
        const id = this.lowerExpr(prop.argument);
        this.nodes.push({ op: 'property-store', ...this.loc(prop), name: '*', args: [dest, id] });
        continue;
      }
      if (prop.value.type === AST_NODE_TYPES.TSEmptyBodyFunctionExpression) {continue;}
      const key = this.keyText(prop.key, prop.computed);
      const valueId = this.lowerExpr(prop.value, key === '<dynamic>' ? undefined : key);
      this.nodes.push({ op: 'property-store', ...this.loc(prop), name: key, args: [dest, valueId] });
    }
    return dest;
  }

  private lowerArray(node: TSESTree.ArrayExpression): number {
    const dest = this.fresh();
    this.nodes.push({ op: 'assign', ...this.loc(node), dest });
    for (const [index, el] of node.elements.entries()) {
      if (el === null) {continue;}
      if (el.type === AST_NODE_TYPES.SpreadElement) {
        const id = this.lowerExpr(el.argument);
        this.nodes.push({ op: 'property-store', ...this.loc(el), name: '*', args: [dest, id] });
        continue;
      }
      const id = this.lowerExpr(el);
      this.nodes.push({ op: 'property-store', ...this.loc(el), name: String(index), args: [dest, id] });
    }
    return dest;
  }

  private lowerTagged(node: TSESTree.TaggedTemplateExpression): number {
    const tag = this.lowerExpr(node.tag);
    const args = node.quasi.expressions.map((expr) => this.lowerExpr(expr));
    const dest = this.fresh();
    const name = node.tag.type === AST_NODE_TYPES.Identifier ? node.tag.name : undefined;
    this.nodes.push({
      op: 'call',
      ...this.loc(node),
      dest,
      object: tag,
      ...(name !== undefined ? { name } : {}),
      ...(args.length > 0 ? { args } : {}),
    });
    return dest;
  }

  private lowerLiteralLike(node: TSESTree.Literal | TSESTree.TemplateLiteral): number {
    const literal = this.pureLiteral(node);
    const dest = this.fresh();
    if (literal !== undefined) {
      this.nodes.push({ op: 'assign', ...this.loc(node), dest, literal });
      return dest;
    }
    if (node.type === AST_NODE_TYPES.TemplateLiteral && node.expressions.length > 0) {
      const args = node.expressions.map((expr) => this.lowerExpr(expr));
      this.nodes.push({ op: 'assign', ...this.loc(node), dest, args });
      return dest;
    }
    this.nodes.push({ op: 'assign', ...this.loc(node), dest });
    return dest;
  }

  private classLabel(node: TSESTree.ClassDeclaration | TSESTree.ClassExpression, hint?: string): string {
    const named = node.id?.name;
    if (named !== undefined) {return named;}
    if (hint !== undefined) {return hint;}
    return '<class>';
  }

  private lowerDecorators(decorators: ReadonlyArray<{ expression: TSESTree.Expression }>): void {
    for (const dec of decorators) {this.lowerExpr(dec.expression);}
  }

  private lowerClassElement(el: TSESTree.ClassElement, className: string): void {
    if (el.type === AST_NODE_TYPES.MethodDefinition && el.value.type === AST_NODE_TYPES.FunctionExpression) {
      this.lowerDecorators(el.decorators);
      this.enqueue(el.value, `${className}.${this.keyText(el.key, el.computed)}`);
      return;
    }
    if (el.type === AST_NODE_TYPES.PropertyDefinition) {
      this.lowerDecorators(el.decorators);
      if (el.value !== null) {this.lowerExpr(el.value);}
      return;
    }
    if (el.type === AST_NODE_TYPES.StaticBlock) {
      for (const stmt of el.body) {this.statement(stmt);}
    }
  }

  private lowerClass(node: TSESTree.ClassDeclaration | TSESTree.ClassExpression, hint?: string): number {
    this.lowerDecorators(node.decorators);
    if (node.superClass !== null) {this.lowerExpr(node.superClass);}
    const className = this.classLabel(node, hint);
    for (const el of node.body.body) {this.lowerClassElement(el, className);}
    const dest = this.fresh();
    this.nodes.push({ op: 'assign', ...this.loc(node), dest, name: className });
    if (node.id !== null) {this.env.set(node.id.name, dest);}
    return dest;
  }

  private lowerExportDefault(node: TSESTree.ExportDefaultDeclaration): void {
    const decl = node.declaration;
    if (
      decl.type === AST_NODE_TYPES.FunctionDeclaration ||
      decl.type === AST_NODE_TYPES.ClassDeclaration ||
      decl.type === AST_NODE_TYPES.VariableDeclaration
    ) {
      this.statement(decl);
      return;
    }
    if (
      decl.type === AST_NODE_TYPES.TSDeclareFunction ||
      decl.type === AST_NODE_TYPES.TSEnumDeclaration ||
      decl.type === AST_NODE_TYPES.TSInterfaceDeclaration ||
      decl.type === AST_NODE_TYPES.TSModuleDeclaration ||
      decl.type === AST_NODE_TYPES.TSTypeAliasDeclaration
    ) {
      return;
    }
    this.lowerExpr(decl);
  }

  private bindLoopLeft(left: TSESTree.ForInStatement['left'] | TSESTree.ForOfStatement['left'], source: number): void {
    if (left.type === AST_NODE_TYPES.VariableDeclaration) {
      for (const decl of left.declarations) {this.defineNames(decl.id, source, decl.id);}
      return;
    }
    this.defineNames(left, source, left);
  }

  private defineParam(pattern: TSESTree.Node): void {
    if (pattern.type === AST_NODE_TYPES.TSParameterProperty) {
      for (const dec of pattern.decorators) {this.lowerExpr(dec.expression);}
      this.defineParam(pattern.parameter);
      return;
    }
    const names = boundNames(pattern);
    this.defineNames(pattern, undefined, pattern);
    for (const name of names) {
      const id = this.env.get(name);
      if (id !== undefined) {this.params.push({ name, id });}
    }
  }

  private defineNames(pattern: TSESTree.Node, source: number | undefined, locNode: TSESTree.Node): void {
    if (pattern.type === AST_NODE_TYPES.AssignmentPattern) {
      const fallback = this.lowerExpr(pattern.right);
      const value = source === undefined ? fallback : this.phi(undefined, [source, fallback], pattern);
      this.defineNames(pattern.left, value, pattern);
      return;
    }
    if (pattern.type === AST_NODE_TYPES.Identifier) {
      this.defineOne(pattern.name, source, pattern);
      return;
    }
    if (pattern.type === AST_NODE_TYPES.RestElement) {
      this.defineNames(pattern.argument, source, locNode);
      return;
    }
    if (pattern.type === AST_NODE_TYPES.ObjectPattern) {
      for (const prop of pattern.properties) {
        if (prop.type === AST_NODE_TYPES.RestElement) {
          this.defineNames(prop, source, locNode);
          continue;
        }
        this.defineNames(prop.value, source, locNode);
      }
      return;
    }
    if (pattern.type === AST_NODE_TYPES.ArrayPattern) {
      for (const el of pattern.elements) {
        if (el !== null) {this.defineNames(el, source, locNode);}
      }
      return;
    }
    for (const name of boundNames(pattern)) {
      this.defineOne(name, source, locNode);
    }
  }

  private defineLiteral(name: string, literal: string | number | boolean | null, locNode: TSESTree.Node): number {
    const dest = this.fresh();
    this.nodes.push({ op: 'assign', ...this.loc(locNode), dest, name, literal });
    this.env.set(name, dest);
    return dest;
  }

  private defineOne(name: string, source: number | undefined, locNode: TSESTree.Node): number {
    const dest = this.fresh();
    this.nodes.push({
      op: 'assign',
      ...this.loc(locNode),
      dest,
      name,
      ...(source !== undefined ? { args: [source] } : {}),
    });
    this.env.set(name, dest);
    return dest;
  }

  private memberRef(node: TSESTree.MemberExpression): { name: string; propId?: number } {
    const named = propName(node);
    if (named !== undefined) {return { name: named };}
    if (!node.computed && node.property.type === AST_NODE_TYPES.PrivateIdentifier) {
      return { name: `#${node.property.name}` };
    }
    return { name: '<dynamic>', propId: this.lowerExpr(node.property) };
  }

  private keyText(key: TSESTree.Node, computed: boolean): string {
    if (!computed && key.type === AST_NODE_TYPES.Identifier) {return key.name;}
    if (!computed && key.type === AST_NODE_TYPES.PrivateIdentifier) {return `#${key.name}`;}
    if (key.type === AST_NODE_TYPES.Literal && (typeof key.value === 'string' || typeof key.value === 'number')) {
      return String(key.value);
    }
    if (computed) {this.lowerExpr(key);}
    return '<dynamic>';
  }

  private mergeTwo(
    before: ReadonlyMap<string, number>,
    left: ReadonlyMap<string, number>,
    right: ReadonlyMap<string, number>,
    locNode: TSESTree.Node,
  ): Map<string, number> {
    const names = new Set<string>([...before.keys(), ...left.keys(), ...right.keys()]);
    const merged = new Map<string, number>();
    for (const name of [...names].sort(cmp)) {
      const l = left.get(name) ?? before.get(name);
      const r = right.get(name) ?? before.get(name);
      if (l === undefined || r === undefined) {
        const only = l ?? r;
        if (only !== undefined) {merged.set(name, only);}
        continue;
      }
      if (l === r) {
        merged.set(name, l);
        continue;
      }
      const dest = this.fresh();
      this.nodes.push({ op: 'phi', ...this.loc(locNode), dest, name, args: [l, r] });
      merged.set(name, dest);
    }
    return merged;
  }

  private phi(name: string | undefined, args: [number, number], locNode: TSESTree.Node): number {
    if (args[0] === args[1]) {return args[0];}
    const dest = this.fresh();
    this.nodes.push({
      op: 'phi',
      ...this.loc(locNode),
      dest,
      args,
      ...(name !== undefined ? { name } : {}),
    });
    return dest;
  }

  private copy(node: TSESTree.Node, args: number[]): number {
    const dest = this.fresh();
    this.nodes.push({ op: 'assign', ...this.loc(node), dest, args });
    return dest;
  }

  private freeName(name: string, node: TSESTree.Node): number {
    const dest = this.fresh();
    this.nodes.push({ op: 'assign', ...this.loc(node), dest, name });
    this.env.set(name, dest);
    return dest;
  }

  private freeValue(node: TSESTree.Node, name: string | undefined): number {
    const dest = this.fresh();
    this.nodes.push({
      op: 'assign',
      ...this.loc(node),
      dest,
      ...(name !== undefined && name.length > 0 ? { name } : {}),
    });
    return dest;
  }

  private unknown(node: TSESTree.Node): number {
    const dest = this.fresh();
    this.nodes.push({ op: 'assign', ...this.loc(node), dest });
    return dest;
  }

  private pureLiteral(node: TSESTree.Node): string | number | boolean | null | undefined {
    if (node.type === AST_NODE_TYPES.Literal) {
      if ('regex' in node && node.regex !== undefined) {return undefined;}
      if (node.value === null) {return null;}
      if (typeof node.value === 'string' || typeof node.value === 'number' || typeof node.value === 'boolean') {
        return node.value;
      }
      return undefined;
    }
    if (node.type === AST_NODE_TYPES.TemplateLiteral && node.expressions.length === 0) {
      const quasi = node.quasis[0];
      return quasi?.value.cooked ?? quasi?.value.raw ?? '';
    }
    return undefined;
  }

  private unwrap(node: TSESTree.Node): TSESTree.Node {
    let current = node;
    for (let depth = 0; depth < 8; depth += 1) {
      if (
        current.type === AST_NODE_TYPES.ChainExpression ||
        current.type === AST_NODE_TYPES.TSAsExpression ||
        current.type === AST_NODE_TYPES.TSTypeAssertion ||
        current.type === AST_NODE_TYPES.TSNonNullExpression ||
        current.type === AST_NODE_TYPES.TSSatisfiesExpression ||
        current.type === AST_NODE_TYPES.TSInstantiationExpression
      ) {
        current = current.expression;
        continue;
      }
      break;
    }
    return current;
  }

  private snapshot(): Map<string, number> {
    return new Map(this.env);
  }

  private fresh(): number {
    const id = this.next;
    this.next += 1;
    return id;
  }

  private loc(node: TSESTree.Node): { file: string; line: number; col: number } {
    return {
      file: this.file,
      line: node.loc?.start.line ?? 0,
      col: node.loc?.start.column ?? 0,
    };
  }
}

function cmp(a: string, b: string): number {
  if (a < b) {return -1;}
  if (a > b) {return 1;}
  return 0;
}
