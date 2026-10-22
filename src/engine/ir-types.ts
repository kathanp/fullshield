/** SSA ops for one function. Locations are 1-based lines and 0-based columns. */

export type IrOp =
  | 'assign'
  | 'call'
  | 'return'
  | 'phi'
  | 'property-load'
  | 'property-store'
  | 'await'
  | 'branch';

export interface IrNode {
  op: IrOp;
  file: string;
  line: number;
  col: number;
  dest?: number;
  args?: number[];
  /** Branch condition, or absent when a loop has no test. */
  cond?: number;
  /** Binding, property, or callee when it is a static name. */
  name?: string;
  /** Set on assigns of a literal, including `null`. Absent means "not a literal". */
  literal?: string | number | boolean | null;
  /** Callee value for a call (`foo` or the object of `obj.method`). */
  object?: number;
}

export interface IrParam {
  name: string;
  id: number;
}

export interface FunctionIr {
  name: string;
  file: string;
  line: number;
  col: number;
  params: IrParam[];
  nodes: IrNode[];
}

/**
 * Import or re-export recorded at module scope.
 * `resolved` is set only when `collectRequires` can see the target file.
 * Barrel re-exports stay unresolved: that walk is private to `runInterproc`.
 */
export interface ImportLink {
  local: string;
  specifier: string;
  imported: string;
  mappedSpecifier?: string;
  packageName?: string;
  exportTarget?: string;
  resolved?: string;
}

export interface ModuleIr {
  file: string;
  imports: ImportLink[];
  functions: FunctionIr[];
}

export interface IrResolveContext {
  /** Project files `collectRequires` may resolve a relative specifier to. */
  files?: ReadonlySet<string>;
  tsPaths?: Readonly<Record<string, readonly string[]>>;
  /** String targets from a package `exports` map. Conditions are not guessed. */
  packageExports?: Readonly<Record<string, string>>;
}

export interface IrQueryFinding {
  file: string;
  line: number;
  col: number;
  sink: string;
  source: string;
}
