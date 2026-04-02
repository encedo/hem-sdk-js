// rollup.browser.config.js — build hem-sdk.browser.js
// node:https / node:http / node:url are in #reqNode (Node.js only code path)
// guarded by `isNode` check — never reached in browser. Mark them external
// so rollup doesn't try to bundle them; a browser build will leave them as
// dead dynamic imports that are never executed.

export default {
  input: 'hem-sdk.js',
  output: {
    file: 'hem-sdk.browser.js',
    format: 'es',
    sourcemap: true,
  },
  external: ['node:https', 'node:http', 'node:url'],
};
