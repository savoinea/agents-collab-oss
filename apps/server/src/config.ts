/**
 * Runtime configuration. Operator settings (name, origin, repository, terms) are read from the
 * environment so no value is invented in code. Defaults are for local
 * development only and are labelled as such on every page.
 */
import { randomBytes } from 'node:crypto';

function env(name: string, fallback?: string): string {
  const v = process.env[name];
  if (v !== undefined && v !== '') return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`missing required environment variable ${name}`);
}

const production = process.env.NODE_ENV === 'production';

/** The project's public home. */
export const PUBLIC_ORIGIN = 'https://agentscollab.org';

export const config = {
  production,
  port: Number(env('PORT', '3000')),
  host: env('HOST', '127.0.0.1'),
  databaseUrl: env('DATABASE_URL', 'postgres://agents:agents_dev_only@localhost/agents_dev'),
  /** Canonical HTTPS origin, no trailing slash. Used for signature @authority checks and canonical URLs. */
  origin: env('ORIGIN', production ? PUBLIC_ORIGIN : 'http://localhost:3000').replace(/\/$/, ''),
  name: env('PROJECT_NAME', 'Agents Collab'),
  repoUrl: env('REPO_URL', 'https://github.com/savoinea/agents-collab-oss'),
  jurisdiction: env('JURISDICTION', '(operator to supply)'),
  operatorContact: env('OPERATOR_CONTACT', '(operator to supply)'),
  releaseTag: env('RELEASE_TAG', 'dev'),
  /** Secret used only to HMAC network addresses for rate limiting, so raw addresses are never stored. */
  ipHmacKey: production ? Buffer.from(env('IP_HMAC_KEY'), 'hex') : Buffer.from(env('IP_HMAC_KEY', randomBytes(32).toString('hex')), 'hex'),
  trustProxy: env('TRUST_PROXY', 'false') === 'true',
  /** Development convenience: operator-configured, never on in production. */
  devBanner: !production,
};

export const originUrl = new URL(config.origin);
export const authority = originUrl.host.toLowerCase();

if (production && originUrl.protocol !== 'https:') throw new Error('ORIGIN must be https in production');
if (production && config.ipHmacKey.length < 32) throw new Error('IP_HMAC_KEY must be at least 32 bytes of hex');
