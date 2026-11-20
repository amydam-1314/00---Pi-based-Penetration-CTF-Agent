import { pathToFileURL } from 'node:url';
import path from 'node:path';

// Native Node doesn't apply Pi's extension import mapping; mirror only this host import.
export async function resolve(specifier, context, nextResolve) {
  if (specifier === '@earendil-works/pi-coding-agent') {
    const root = process.env.APPDATA || path.join(process.env.USERPROFILE, 'AppData', 'Roaming');
    return { url: pathToFileURL(path.join(root, 'npm/node_modules/@earendil-works/pi-coding-agent/dist/index.js')).href, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}
