/**
 * Fetch-based transport for non-browser clients (test correspondent, monitor). Every write is an
 * RFC 9421 signed request; reads use the session cookie obtained by signing a login challenge.
 */
import { signChallenge, signRequest, type IdentityKeys } from '@acp/protocol';
import type { Transport } from './index';

export class HttpTransport implements Transport {
  private cookie = '';
  private readonly origin: URL;

  constructor(origin: string, private readonly keys: IdentityKeys) {
    this.origin = new URL(origin);
  }

  private capture(res: Response): void {
    const sc = res.headers.get('set-cookie');
    const m = sc && /acp_session=([^;]*)/.exec(sc);
    if (m) this.cookie = m[1] ? `acp_session=${m[1]}` : '';
  }

  private async parse<T>(res: Response): Promise<T> {
    const data = (await res.json().catch(() => ({ ok: false, message: `status ${res.status}` }))) as Record<string, unknown>;
    if (!res.ok || data.ok === false) throw Object.assign(new Error(String(data.message ?? res.status)), { code: data.error, status: res.status, data });
    return data as T;
  }

  async login(): Promise<void> {
    const c = await this.get<{ challenge: string; audience: string }>('/api/login/challenge');
    if (c.audience !== this.origin.origin) throw new Error('login challenge audience does not match the configured origin');
    const res = await fetch(new URL('/api/login', this.origin), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: this.keys.address, challenge: c.challenge, signature: signChallenge(this.keys, c.challenge, c.audience) }),
    });
    this.capture(res);
    await this.parse(res);
  }

  async get<T = Record<string, unknown>>(path: string): Promise<T> {
    const res = await fetch(new URL(path, this.origin), { headers: this.cookie ? { cookie: this.cookie, accept: 'application/json' } : { accept: 'application/json' } });
    this.capture(res);
    if (res.status === 401 && this.cookie) {
      await this.login();
      return this.get(path);
    }
    return this.parse<T>(res);
  }

  async post<T = Record<string, unknown>>(path: string, body: unknown): Promise<T> {
    const bytes = new TextEncoder().encode(JSON.stringify(body));
    const url = new URL(path, this.origin);
    const headers = signRequest(this.keys, { method: 'POST', authority: this.origin.host.toLowerCase(), path: url.pathname, query: url.search || '?', body: bytes });
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers, ...(this.cookie ? { cookie: this.cookie } : {}) }, body: bytes });
    this.capture(res);
    return this.parse<T>(res);
  }
}
