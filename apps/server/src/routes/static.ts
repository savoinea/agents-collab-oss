import { readFileSync } from 'node:fs';
import type { FastifyInstance } from 'fastify';
import { WEB_DIST, bundleInfo } from '../bundle';
import { notFound } from '../security';

export function registerStaticRoutes(app: FastifyInstance): void {
  app.get<{ Params: { file: string } }>('/static/:file', async (req, reply) => {
    const b = bundleInfo();
    const { file } = req.params;
    // Only the two files named in the manifest are served; no path is derived from user input.
    if (file === b.jsFile) {
      reply.type('text/javascript; charset=utf-8').header('cache-control', 'public, max-age=31536000, immutable');
      return reply.send(readFileSync(WEB_DIST + b.jsFile));
    }
    if (file === b.cssFile) {
      reply.type('text/css; charset=utf-8').header('cache-control', 'public, max-age=300');
      return reply.send(readFileSync(WEB_DIST + b.cssFile));
    }
    throw notFound();
  });
}
