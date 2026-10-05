/**
 * The served client bundle is identified by its SHA-256 (shown in the footer and published
 * by CI) and loaded with a Subresource Integrity attribute. The manifest is produced by
 * scripts/build.mjs, which builds deterministically.
 */
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const WEB_DIST = fileURLToPath(new URL('../../../dist/web/', import.meta.url));

export interface BundleInfo {
  jsFile: string;
  jsSha256Hex: string;
  jsSri: string;
  cssFile: string;
  cssSri: string;
}

let cached: BundleInfo | null = null;

export function bundleInfo(): BundleInfo {
  if (cached) return cached;
  const path = WEB_DIST + 'manifest.json';
  if (!existsSync(path)) throw new Error('client bundle not built: run `npm run build` first');
  cached = JSON.parse(readFileSync(path, 'utf8')) as BundleInfo;
  return cached;
}

export function resetBundleCache(): void {
  cached = null;
}
