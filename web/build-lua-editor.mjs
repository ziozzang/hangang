import { build } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';

// Keep the MIT notices inside the shipped bundle, including static binaries
// that embed only web/lua-editor.js and not node_modules.
const bundledPackages = [
  '@codemirror/autocomplete',
  '@codemirror/commands',
  '@codemirror/language',
  '@codemirror/legacy-modes',
  '@codemirror/state',
  '@codemirror/view',
  '@lezer/common',
  '@lezer/highlight',
  '@lezer/lr',
  '@marijn/find-cluster-break',
  'crelt',
  'style-mod',
  'w3c-keyname',
];

const result = await build({
  entryPoints: ['lua-editor-src.js'],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  minify: true,
  legalComments: 'none',
  write: false,
});
const notices = await Promise.all(bundledPackages.map(async (name) => {
  const license = await readFile(`node_modules/${name}/LICENSE`, 'utf8');
  return `${name}\n${license.trim()}\n`;
}));
const legal = `\n/*! Bundled third-party MIT license notices\n${notices.join('\n').replaceAll('*/', '* /')}*/\n`;
await writeFile('lua-editor.js', result.outputFiles[0].text + legal);
