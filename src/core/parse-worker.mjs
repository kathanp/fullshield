import { parentPort, workerData } from 'node:worker_threads';
import { parse } from '@typescript-eslint/typescript-estree';

const ast = parse(workerData.code, {
  loc: true,
  range: true,
  comment: false,
  jsx: true,
  errorOnUnknownASTType: false,
  errorOnTypeScriptSyntacticAndSemanticIssues: false,
});
parentPort.postMessage(ast);
