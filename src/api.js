import { AwsCliError } from './aws-cli.js';
import { TrivyScanService } from './trivy.js';

const MAX_BODY_BYTES = 16 * 1024;
const MAX_SBOM_BODY_BYTES = 20 * 1024 * 1024;

export function sendJson(response, status, value) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  response.end(JSON.stringify(value));
}

export function sendError(response, error) {
  const known = error instanceof AwsCliError;
  const status = known ? error.status : 500;
  const code = known ? error.code : 'INTERNAL_ERROR';
  const message = known ? error.message : 'The app could not complete this request. Try again.';
  sendJson(response, status, { error: { code, message } });
}

async function readJsonBody(request, maxBytes = MAX_BODY_BYTES) {
  const contentType = request.headers['content-type'];
  const type = typeof contentType === 'string' ? contentType.split(';', 1)[0].trim().toLowerCase() : '';
  if (type !== 'application/json') {
    throw new AwsCliError(415, 'CONTENT_TYPE', 'Send JSON with Content-Type: application/json.');
  }
  const declaredLength = Number(request.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new AwsCliError(413, 'BODY_TOO_LARGE', 'The request body is too large.');
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) {
      throw new AwsCliError(413, 'BODY_TOO_LARGE', 'The request body is too large.');
    }
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('Expected a JSON object');
    }
    return value;
  } catch {
    throw new AwsCliError(400, 'INVALID_JSON', 'The request body must be a valid JSON object.');
  }
}

function queryParams(url) {
  return {
    profile: url.searchParams.get('profile'),
    region: url.searchParams.get('region'),
    repository: url.searchParams.get('repository'),
    digest: url.searchParams.get('digest'),
    platform: url.searchParams.get('platform'),
    nextToken: url.searchParams.get('nextToken'),
  };
}

export function createApi(aws, scans = new TrivyScanService(aws)) {
  let sbomUploadActive = false;
  const handleApi = async function handleApi(request, response, url) {
    const { pathname } = url;
    const params = queryParams(url);
    if (request.method === 'GET' && pathname === '/api/profiles') {
      return sendJson(response, 200, { profiles: await aws.listProfiles(url.searchParams.get('refresh') === '1') });
    }
    if (request.method === 'GET' && pathname === '/api/auth-method') {
      return sendJson(response, 200, { authMethod: await aws.authMethod(params.profile) });
    }
    if (request.method === 'POST' && pathname === '/api/auth/mfa') {
      const body = await readJsonBody(request);
      return sendJson(response, 200, await aws.authenticateRoleMfa(body.profile, body.region, body.code));
    }
    if (request.method === 'GET' && pathname === '/api/identity') {
      return sendJson(response, 200, await aws.identity(params.profile, params.region));
    }
    if (request.method === 'GET' && pathname === '/api/repositories') {
      return sendJson(response, 200, await aws.repositories(params.profile, params.region, params.nextToken));
    }
    if (request.method === 'GET' && pathname === '/api/images') {
      return sendJson(response, 200, await aws.images(params.profile, params.region, params.repository, params.nextToken));
    }
    if (request.method === 'GET' && pathname === '/api/scanner/status') {
      return sendJson(response, 200, await scans.status());
    }
    if (request.method === 'GET' && pathname === '/api/scans/latest') {
      return sendJson(response, 200, await scans.latest(params));
    }
    if (request.method === 'POST' && pathname === '/api/scans') {
      const body = await readJsonBody(request);
      return sendJson(response, 202, await scans.start(body));
    }
    if (request.method === 'POST' && pathname === '/api/scans/sbom') {
      if (sbomUploadActive) {
        throw new AwsCliError(429, 'SBOM_UPLOAD_BUSY', 'Another SBOM upload is being processed. Wait for it to finish, then retry.');
      }
      sbomUploadActive = true;
      try {
        const body = await readJsonBody(request, MAX_SBOM_BODY_BYTES);
        return sendJson(response, 202, await scans.startSbom(body));
      } finally {
        sbomUploadActive = false;
      }
    }
    const scanId = /^\/api\/scans\/([a-f0-9-]{36})$/.exec(pathname)?.[1];
    if (scanId && request.method === 'GET') {
      return sendJson(response, 200, scans.get(scanId));
    }
    if (scanId && request.method === 'DELETE') {
      return sendJson(response, 200, scans.cancel(scanId));
    }
    if (['/api/profiles', '/api/auth-method', '/api/auth/mfa', '/api/identity', '/api/repositories', '/api/images',
      '/api/scanner/status', '/api/scans/latest', '/api/scans', '/api/scans/sbom'].includes(pathname) || scanId) {
      throw new AwsCliError(405, 'METHOD_NOT_ALLOWED', 'This API endpoint does not support that method.');
    }
    throw new AwsCliError(404, 'NOT_FOUND', 'This API endpoint does not exist.');
  };
  handleApi.dispose = () => scans.dispose();
  return handleApi;
}
