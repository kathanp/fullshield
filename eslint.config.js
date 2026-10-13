import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**', 'node_modules/**', 'test/fixtures/**'],
  },
  {
    files: ['**/*.{js,mjs}'],
    ...js.configs.recommended,
    languageOptions: {
      globals: { ...globals.node },
    },
  },
  {
    files: ['**/*.ts'],
    extends: [...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // TSESTree.Node['type'] is a string enum; comparing it to AST type names
    // is the documented way to narrow nodes and is not an unsafe comparison.
    files: ['src/modules/sast/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-enum-comparison': 'off',
    },
  },
);
