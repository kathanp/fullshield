import tseslint from 'typescript-eslint';

const root = process.env.QUALITY_ROOT ?? process.cwd();
const typed = process.env.QUALITY_TYPED === '1';

const rules = {
  eqeqeq: 'error',
  'no-var': 'error',
  'prefer-const': 'error',
  curly: 'error',
  'no-throw-literal': 'error',
  'default-case-last': 'error',
  'no-implicit-coercion': 'error',
  '@typescript-eslint/no-explicit-any': 'error',
  complexity: ['error', 15],
  'max-depth': ['error', 4],
  'max-params': ['error', 5],
  'max-lines-per-function': ['error', 80],
};

if (typed) {
  rules['@typescript-eslint/no-floating-promises'] = 'error';
  rules['@typescript-eslint/no-misused-promises'] = 'error';
  rules['@typescript-eslint/switch-exhaustiveness-check'] = 'error';
}

/** Phase 94 rules. Error on changed files (Q1) and counted across src (Q2). */
export default tseslint.config({
  files: ['**/*.ts'],
  plugins: { '@typescript-eslint': tseslint.plugin },
  languageOptions: {
    parser: tseslint.parser,
    parserOptions: typed
      ? { projectService: true, tsconfigRootDir: root }
      : { ecmaVersion: 2022, sourceType: 'module' },
  },
  rules,
});
