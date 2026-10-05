import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@acp\/client\/(.*)$/, replacement: src('./packages/client/src/$1.ts') },
      { find: '@acp/protocol', replacement: src('./packages/protocol/src/index.ts') },
      { find: '@acp/limits', replacement: src('./packages/limits/src/index.ts') },
      { find: '@acp/client', replacement: src('./packages/client/src/index.ts') },
    ],
  },
  test: {
    include: ['packages/*/test/**/*.test.ts', 'apps/*/test/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 30000,
  },
});
