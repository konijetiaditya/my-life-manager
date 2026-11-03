// Copies the PDF viewer's fonts / colour tables / wasm decoders into public/ so the app never needs the internet.
import { cpSync, mkdirSync, rmSync } from 'node:fs';
const src = 'node_modules/pdfjs-dist';
rmSync('public/pdfjs', { recursive: true, force: true });
mkdirSync('public/pdfjs', { recursive: true });
for (const d of ['cmaps', 'standard_fonts', 'wasm']) cpSync(`${src}/${d}`, `public/pdfjs/${d}`, { recursive: true });
console.log('pdfjs assets copied');
