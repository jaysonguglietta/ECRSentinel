import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { dirname, extname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AwsCliError, AwsCliService } from './src/aws-cli.js';
import { createApi, sendError } from './src/api.js';
import { TrivyScanService } from './src/trivy.js';

const projectDirectory = dirname(fileURLToPath(import.meta.url));
const defaultPublicDirectory = join(projectDirectory, 'public');
const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

function setSecurityHeaders(response) {
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
}

function sameOriginRequest(request, port) {
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  if (!hosts.has(request.headers.host)) return false;
  const origin = request.headers.origin;
  if (origin && !hosts.has(origin.replace(/^http:\/\//, ''))) return false;
  if (origin && !origin.startsWith('http://')) return false;
  return true;
}

function hasApiToken(request, token) {
  const received = request.headers['x-ecr-sentinel-token'];
  if (typeof received !== 'string') return false;
  const actual = Buffer.from(received, 'utf8');
  const expected = Buffer.from(token, 'utf8');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

async function serveStatic(request, response, url, publicDirectory) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    throw new AwsCliError(405, 'METHOD_NOT_ALLOWED', 'Only GET and HEAD are supported for static files.');
  }
  let pathName;
  try {
    pathName = decodeURIComponent(url.pathname);
  } catch {
    throw new AwsCliError(400, 'INVALID_PATH', 'The requested path is invalid.');
  }
  if (pathName === '/') pathName = '/index.html';
  if (pathName.includes('\\') || pathName.includes('\0') || pathName.split('/').some((part) => part.startsWith('.'))) {
    throw new AwsCliError(404, 'NOT_FOUND', 'The requested file does not exist.');
  }
  const directory = await realpath(publicDirectory);
  const candidate = resolve(directory, `.${pathName}`);
  if (!candidate.startsWith(`${directory}${sep}`)) {
    throw new AwsCliError(404, 'NOT_FOUND', 'The requested file does not exist.');
  }
  let file;
  try {
    file = await realpath(candidate);
    if (!file.startsWith(`${directory}${sep}`) || !(await stat(file)).isFile()) {
      throw new Error('Outside public directory');
    }
  } catch {
    throw new AwsCliError(404, 'NOT_FOUND', 'The requested file does not exist.');
  }
  const extension = extname(file).toLowerCase();
  if (!CONTENT_TYPES[extension]) {
    throw new AwsCliError(404, 'NOT_FOUND', 'The requested file does not exist.');
  }
  const body = await readFile(file);
  response.writeHead(200, {
    'Content-Type': CONTENT_TYPES[extension],
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
  });
  response.end(request.method === 'HEAD' ? undefined : body);
}

export function createAppServer({ aws = new AwsCliService(), scans, publicDirectory = defaultPublicDirectory, token = randomBytes(32).toString('hex') } = {}) {
  const handleApi = createApi(aws, scans ?? new TrivyScanService(aws));
  const server = createServer(async (request, response) => {
    setSecurityHeaders(response);
    try {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : null;
      if (!port || !sameOriginRequest(request, port)) {
        throw new AwsCliError(403, 'LOCAL_ONLY', 'Open the app from its 127.0.0.1 address.');
      }
      if (!request.url || request.url.length > 10_000) {
        throw new AwsCliError(414, 'URL_TOO_LONG', 'The request URL is too long.');
      }
      const url = new URL(request.url, `http://127.0.0.1:${port}`);
      if (url.pathname.startsWith('/api/')) {
        if (!hasApiToken(request, token)) {
          throw new AwsCliError(403, 'INVALID_API_TOKEN', 'Open the launch URL printed by npm start, then try again.');
        }
        await handleApi(request, response, url);
      } else {
        await serveStatic(request, response, url, publicDirectory);
      }
    } catch (error) {
      if (!response.headersSent) sendError(response, error);
      else response.destroy();
    }
  });
  server.requestTimeout = 20_000;
  server.headersTimeout = 10_000;
  server.maxHeadersCount = 32;
  server.on('close', () => { void handleApi.dispose().catch(() => {}); });
  return { server, token };
}

function parsePort(value) {
  if (value === undefined) return 4173;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer from 1 to 65535.');
  }
  return port;
}

if (process.argv[1] && isAbsolute(process.argv[1]) && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { server, token } = createAppServer();
  const port = parsePort(process.env.PORT);
  server.listen(port, '127.0.0.1', () => {
    console.log(`Open ECR Sentinel: http://127.0.0.1:${port}/#token=${token}`);
  });
  server.on('error', (error) => {
    console.error(`Could not start ECR Sentinel: ${error.message}`);
    process.exitCode = 1;
  });
}
