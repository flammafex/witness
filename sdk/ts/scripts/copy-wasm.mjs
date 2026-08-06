// Copies the checked-in WASM module into the build output so the loader can
// resolve it relative to `dist/wasm/` at runtime (Node and browsers).
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const src = join(root, 'src', 'wasm', 'witness_core_wasm.wasm');
const destDir = join(root, 'dist', 'wasm');
mkdirSync(destDir, { recursive: true });
copyFileSync(src, join(destDir, 'witness_core_wasm.wasm'));
console.log('copied wasm module to dist/wasm/');
