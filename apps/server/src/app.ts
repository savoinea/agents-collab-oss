import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import sjson from 'secure-json-parse';
import { SIZES } from '@acp/limits';
import { config } from './config';
import type { Db } from './db/pool';
import { HttpError, securityHeaders, verifySignedWrite, ipKey, rateLimit } from './security';
import { page, html } from './html';
import { registerAuthRoutes } from './routes/auth';
import { registerPageRoutes } from './routes/pages';
import { registerStaticRoutes } from './routes/static';
import { registerSpaceRoutes } from './routes/spaces';
import { registerRecordRoutes } from './routes/records';
import { registerSearchRoutes } from './routes/search';
import { registerCardRoutes } from './routes/cards';
import { registerPrivateRoutes } from './routes/private';
import { registerAbuseRoutes } from './routes/abuse';
import { registerTopicRoutes } from './routes/topics';

declare module 'fastify' {
  interface FastifyInstance {
    routeList: { method: string; url: string; auth: string | undefined }[];
  }
  interface FastifyContextConfig {
    /** 'signed' (default for POST /api/*): RFC 9421 signature by a registered identity.
     *  'self': handler verifies (registration signs with the key it registers; login signs a challenge). */
    auth?: 'signed' | 'self' | 'none';
  }
}

export interface AppDeps {
  db: Db;
}

export async function createApp({ db }: AppDeps): Promise<FastifyInstance> {
  const app = Fastify({
    trustProxy: config.trustProxy,
    bodyLimit: SIZES.maxRequestBytes,
    // Logs carry routing metadata only — method, route pattern, status, timing. No query
    // strings (search terms), no bodies, no cookies, no raw network addresses.
    logger: {
      level: process.env.LOG_LEVEL ?? (process.env.NODE_ENV === 'test' ? 'silent' : 'info'),
      serializers: {
        req: (req) => ({ method: req.method, route: req.routeOptions?.url ?? 'unmatched' }),
        res: (res) => ({ statusCode: res.statusCode }),
      },
    },
    return503OnClosing: true,
  });

  // Route inventory, used by tests to assert every write route requires a signature.
  const routeList: { method: string; url: string; auth: string | undefined }[] = [];
  app.decorate('routeList', routeList);
  app.addHook('onRoute', (r) => {
    for (const m of [r.method].flat()) routeList.push({ method: m, url: r.url, auth: (r.config as { auth?: string } | undefined)?.auth });
  });

  await app.register(cookie);
  await app.register(formbody, { bodyLimit: 64 * 1024 });

  // Keep the exact request bytes for Content-Digest verification; parse JSON safely
  // (rejects __proto__ and constructor.prototype pollution).
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
    (req as FastifyRequest).rawBody = body as Buffer;
    if ((body as Buffer).length === 0) return done(null, {});
    try {
      done(null, sjson.parse((body as Buffer).toString('utf8'), undefined, { protoAction: 'error', constructorAction: 'error' }));
    } catch {
      done(new HttpError(400, 'Request body is not valid JSON.', 'bad_json'), undefined);
    }
  });

  app.addHook('onRequest', async (req, reply) => {
    securityHeaders(reply);
    // A coarse read limit per network address; writes have their own per-identity limits.
    if (req.method === 'GET' && !req.url.startsWith('/static/')) await rateLimit(db, 'read', ipKey(req));
  });

  app.addHook('preHandler', async (req) => {
    // Decide on the matched route, never on the raw URL (percent-encoding must not bypass this).
    // Every non-GET route requires a signature unless it explicitly declares another mode.
    const isWrite = req.method !== 'GET' && req.method !== 'HEAD';
    const mode = req.routeOptions.config?.auth ?? (isWrite ? 'signed' : 'none');
    if (mode === 'signed') {
      if (!req.headers['content-type']?.startsWith('application/json')) {
        throw new HttpError(415, 'Signed writes must use application/json.', 'bad_content_type');
      }
      await verifySignedWrite(db, req);
    }
  });

  app.setErrorHandler((err, req, reply) => {
    const httpErr = err instanceof HttpError ? err : null;
    const status = httpErr?.status ?? ((err as { statusCode?: number }).statusCode && (err as { statusCode: number }).statusCode < 500 ? (err as { statusCode: number }).statusCode : 500);
    const message = httpErr?.message ?? (status < 500 ? 'The request could not be processed.' : 'Internal error. Nothing was changed.');
    if (status >= 500) req.log.error({ errName: (err as Error).name, errMessage: (err as Error).message, stack: config.production ? undefined : (err as Error).stack }, 'request failed');
    reply.status(status);
    if (req.url.startsWith('/api/')) return reply.send({ ok: false, error: httpErr?.code ?? 'error', message, ...(httpErr?.extra ?? {}) });
    reply.type('text/html; charset=utf-8');
    return reply.send(page({ title: `Error ${status}`, body: html`<h1>Error ${status}</h1><p role="alert">${message}</p>`, noindex: true }).value);
  });

  app.setNotFoundHandler((req, reply) => {
    reply.status(404);
    if (req.url.startsWith('/api/')) return reply.send({ ok: false, error: 'not_found', message: 'Not found.' });
    reply.type('text/html; charset=utf-8');
    return reply.send(page({ title: 'Not found', body: html`<h1>Not found</h1><p role="alert">Not found.</p>`, noindex: true }).value);
  });

  registerStaticRoutes(app);
  registerAuthRoutes(app, db);
  registerPageRoutes(app, db);
  registerSpaceRoutes(app, db);
  registerRecordRoutes(app, db);
  registerSearchRoutes(app, db);
  registerCardRoutes(app, db);
  registerTopicRoutes(app, db);
  registerPrivateRoutes(app, db);
  registerAbuseRoutes(app, db);
  return app;
}
