// Google Drive Proxy v4.1.0
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (url.pathname === '/health') {
        return new Response('OK', { status: 200, headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
      }
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error('Worker error:', error);
      return jsonResponse({ error: 'Server error', details: error.message }, 500);
    }
  }
};

async function handleRequest(request, env, ctx) {
  if (request.method === 'OPTIONS') return new Response(null, { headers: getCorsHeaders() });
  if (!['GET', 'HEAD'].includes(request.method)) return jsonResponse({ error: 'Method not allowed' }, 405);

  const url = new URL(request.url);

  // ─── DEBUG ENDPOINT ──────────────────────────────────────────────────────
  if (url.pathname === '/debug') {
    const fileId = url.searchParams.get('id');
    if (!fileId) return jsonResponse({ error: 'add ?id=FILE_ID' }, 400);

    const accounts = getAllServiceAccounts(env);
    if (accounts.length === 0) return jsonResponse({ error: 'No SA found in env', hint: 'Add GOOGLE_SERVICE_ACCOUNT env var in Cloudflare Worker settings' }, 500);

    const sa = accounts[0];
    const results = {
      sa_email: sa.client_email,
      sa_project: sa.project_id,
      total_accounts: accounts.length,
      token: null,
      token_error: null,
      metadata: null,
      metadata_error: null,
      metadata_raw_status: null
    };

    try {
      const now = Math.floor(Date.now() / 1000);
      const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const claims = base64UrlEncode(JSON.stringify({
        iss: sa.client_email,
        scope: 'https://www.googleapis.com/auth/drive',
        aud: 'https://oauth2.googleapis.com/token',
        exp: now + 3600,
        iat: now
      }));
      const sigInput = `${header}.${claims}`;
      const privateKey = await importPrivateKey(sa.private_key);
      const signature = await crypto.subtle.sign(
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        privateKey,
        new TextEncoder().encode(sigInput)
      );
      const jwt = `${sigInput}.${base64UrlEncode(signature)}`;

      const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
      });

      const tokenBody = await tokenResp.json();
      if (tokenResp.ok) {
        results.token = tokenBody.access_token?.slice(0, 30) + '...';
      } else {
        results.token_error = tokenBody;
      }

      if (tokenBody.access_token) {
        const metaResp = await fetch(
          `https://www.googleapis.com/drive/v3/files/${fileId}?fields=name,size,mimeType`,
          { headers: { 'Authorization': `Bearer ${tokenBody.access_token}` } }
        );
        results.metadata_raw_status = metaResp.status;
        const metaBody = await metaResp.json();
        if (metaResp.ok) {
          results.metadata = metaBody;
        } else {
          results.metadata_error = metaBody;
        }
      }
    } catch (e) {
      results.token_error = e.message;
    }

    return jsonResponse(results, 200);
  }
  // ─── END DEBUG ───────────────────────────────────────────────────────────

  let targetUrl = url.searchParams.get('url');
  const fileId = url.searchParams.get('id');
  const forceApi = url.searchParams.get('api') === 'true';
  const forceDirect = url.searchParams.get('direct') === 'true';

  let extractedFileId = fileId;
  if (!extractedFileId && targetUrl?.includes('drive.google.com')) {
    extractedFileId = extractGoogleDriveId(targetUrl);
  }

  if (!targetUrl && !extractedFileId) {
    return jsonResponse({
      error: 'Missing url or id parameter',
      examples: { driveId: '?id=FILE_ID', video: '?url=https://example.com/video.mp4', m3u8: '?url=https://example.com/playlist.m3u8' }
    }, 400);
  }

  // ── SA/API path ──
  if (extractedFileId && !forceDirect && (forceApi || hasServiceAccounts(env))) {
    try {
      return await handleDriveApiRequest(request, extractedFileId, env, ctx);
    } catch (apiError) {
      console.warn('API path failed, falling back to direct:', apiError.message);
      if (apiError.message.includes('not found')) {
        return jsonResponse({ error: 'File not found' }, 404);
      }
    }
  }

  // ── Direct path ──
  if (extractedFileId && !targetUrl) {
    targetUrl = buildGoogleDriveUrl(extractedFileId);
  }

  if (!targetUrl) return jsonResponse({ error: 'Could not determine target URL' }, 400);

  const validation = validateTargetUrl(targetUrl);
  if (!validation.valid) return jsonResponse({ error: validation.error }, validation.status);

  if (isM3U8Url(targetUrl)) {
    return await handleM3U8Request(request, targetUrl, validation.url, ctx, url.searchParams);
  }

  return await fetchDirect(request, targetUrl, validation.url, ctx, url.searchParams);
}

// ─── GOOGLE DRIVE API ────────────────────────────────────────────────────────

function hasServiceAccounts(env) {
  return !!(env.GOOGLE_SERVICE_ACCOUNT || env.GOOGLE_SERVICE_ACCOUNT_1);
}

function getAllServiceAccounts(env) {
  const accounts = [];
  for (let i = 0; i <= 10; i++) {
    const key = i === 0 ? 'GOOGLE_SERVICE_ACCOUNT' : `GOOGLE_SERVICE_ACCOUNT_${i}`;
    if (env[key]) {
      try {
        accounts.push(JSON.parse(env[key]));
      } catch {
        console.error(`Invalid JSON in ${key}`);
      }
    }
  }
  return accounts;
}

async function handleDriveApiRequest(request, fileId, env, ctx) {
  const serviceAccounts = getAllServiceAccounts(env);
  if (serviceAccounts.length === 0) throw new Error('No service accounts configured');

  let lastError = null;
  for (let i = 0; i < serviceAccounts.length; i++) {
    try {
      const result = await tryServiceAccount(request, fileId, serviceAccounts[i], i, ctx);
      if (result) return result;
    } catch (error) {
      console.warn(`SA[${i}] failed: ${error.message}`);
      lastError = error;
      if (error.message.includes('not found')) throw error;
    }
  }
  throw lastError || new Error('All service accounts failed');
}

async function tryServiceAccount(request, fileId, serviceAccount, accountIndex, ctx) {
  const accessToken = await getGoogleAccessToken(serviceAccount, ctx);
  if (!accessToken) throw new Error(`SA[${accountIndex}]: failed to get access token`);

  const metaUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?fields=size,name,mimeType,md5Checksum,modifiedTime`;
  const metaResp = await fetch(metaUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });

  if (!metaResp.ok) {
    const body = await metaResp.text().catch(() => '');
    console.error(`SA[${accountIndex}] metadata ${metaResp.status}: ${body}`);
    if (metaResp.status === 404) throw new Error('File not found');
    if (metaResp.status === 401) throw new Error(`SA[${accountIndex}]: 401 invalid token`);
    if (metaResp.status === 403) throw new Error(`SA[${accountIndex}]: 403 no access`);
    throw new Error(`Metadata failed: ${metaResp.status}`);
  }

  const metadata = await metaResp.json();
  const fileName = metadata.name || 'download';
  const fileSize = parseInt(metadata.size || '0', 10);
  const mimeType = metadata.mimeType || 'application/octet-stream';
  const isGoogleDoc = mimeType.startsWith('application/vnd.google-apps.');
  const rangeHeader = request.headers.get('Range');

  const downloadUrl = isGoogleDoc
    ? buildExportUrl(fileId, mimeType)
    : `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;

  // ── HEAD ──
  if (request.method === 'HEAD') {
    const headers = new Headers();
    if (!isGoogleDoc && fileSize > 0) headers.set('Content-Length', String(fileSize));
    headers.set('Content-Type', isGoogleDoc ? 'application/pdf' : mimeType);
    headers.set('Content-Disposition', buildContentDisposition(fileName));
    headers.set('Accept-Ranges', isGoogleDoc ? 'none' : 'bytes');
    headers.set('X-Drive-API', 'true');
    headers.set('X-Account', String(accountIndex));
    if (metadata.md5Checksum && !isGoogleDoc) headers.set('ETag', `"${metadata.md5Checksum}"`);
    if (metadata.modifiedTime) headers.set('Last-Modified', new Date(metadata.modifiedTime).toUTCString());
    addCorsHeaders(headers);
    return new Response(null, { status: 200, headers });
  }

  // ── GET ──
  const downloadHeaders = new Headers({
    'Authorization': `Bearer ${accessToken}`,
    'Connection': 'keep-alive'
  });
  if (rangeHeader && !isGoogleDoc) downloadHeaders.set('Range', rangeHeader);

  const response = await fetch(downloadUrl, {
    method: 'GET',
    headers: downloadHeaders,
    cf: {
      cacheTtl: isVideoMimeType(mimeType) ? 86400 : 3600,
      cacheEverything: isVideoMimeType(mimeType)
    }
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    console.error(`SA[${accountIndex}] download ${response.status}: ${body}`);
    throw new Error(`Download failed: ${response.status}`);
  }

  if ([101, 204, 205, 304].includes(response.status)) {
    const h = new Headers(response.headers);
    addCorsHeaders(h);
    return new Response(null, { status: response.status, headers: h });
  }

  const finalHeaders = new Headers();
  finalHeaders.set('Content-Type', response.headers.get('Content-Type') || mimeType);
  finalHeaders.set('Content-Disposition', buildContentDisposition(fileName));
  finalHeaders.set('Accept-Ranges', isGoogleDoc ? 'none' : 'bytes');
  finalHeaders.set('X-Drive-API', 'true');
  finalHeaders.set('X-Account', String(accountIndex));
  finalHeaders.set('Cache-Control', 'public, max-age=86400');

  if (response.status === 206) {
    ['Content-Range', 'Content-Length'].forEach(h => {
      if (response.headers.has(h)) finalHeaders.set(h, response.headers.get(h));
    });
    finalHeaders.set('Cache-Control', 'public, max-age=86400, immutable');
    addCorsHeaders(finalHeaders);
    return new Response(response.body, { status: 206, headers: finalHeaders });
  }

  if (response.headers.has('Content-Length')) {
    finalHeaders.set('Content-Length', response.headers.get('Content-Length'));
  } else if (!isGoogleDoc && fileSize > 0) {
    finalHeaders.set('Content-Length', String(fileSize));
  }

  if (metadata.md5Checksum && !isGoogleDoc) finalHeaders.set('ETag', `"${metadata.md5Checksum}"`);
  if (metadata.modifiedTime) finalHeaders.set('Last-Modified', new Date(metadata.modifiedTime).toUTCString());

  addCorsHeaders(finalHeaders);
  return new Response(response.body, { status: 200, headers: finalHeaders });
}

// ─── GOOGLE AUTH ─────────────────────────────────────────────────────────────

async function getGoogleAccessToken(serviceAccount, ctx) {
  const email = serviceAccount.client_email;
  const cache = caches.default;
  const cacheKey = new Request(`https://auth.internal/v2/${btoa(email).replace(/=/g, '')}`);

  try {
    const cached = await cache.match(cacheKey);
    if (cached) {
      const token = await cached.text();
      if (token && token.length > 20) return token;
    }
  } catch { /* ignore */ }

  try {
    const now = Math.floor(Date.now() / 1000);
    const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const claims = base64UrlEncode(JSON.stringify({
      iss: email,
      scope: 'https://www.googleapis.com/auth/drive',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now
    }));

    const sigInput = `${header}.${claims}`;
    const privateKey = await importPrivateKey(serviceAccount.private_key);
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      privateKey,
      new TextEncoder().encode(sigInput)
    );

    const jwt = `${sigInput}.${base64UrlEncode(signature)}`;

    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    if (!tokenResp.ok) {
      const err = await tokenResp.text().catch(() => '');
      throw new Error(`Token exchange failed ${tokenResp.status}: ${err}`);
    }

    const { access_token } = await tokenResp.json();
    if (!access_token) throw new Error('No access_token in response');

    ctx.waitUntil(cache.put(cacheKey, new Response(access_token, {
      headers: { 'Cache-Control': 'max-age=3300' }
    })));

    return access_token;
  } catch (error) {
    console.error('getGoogleAccessToken error:', error.message);
    return null;
  }
}

async function importPrivateKey(pemKey) {
  const pemContents = pemKey
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const binaryKey = base64Decode(pemContents);
  return await crypto.subtle.importKey(
    'pkcs8', binaryKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );
}

// ─── M3U8 ────────────────────────────────────────────────────────────────────

async function handleM3U8Request(request, targetUrl, parsedTarget, ctx, params) {
  const proxyHeaders = buildHeaders(request, parsedTarget, params);
  const response = await fetch(targetUrl, { method: 'GET', headers: proxyHeaders, redirect: 'follow' });

  if (!response.ok) return jsonResponse({ error: 'Failed to fetch playlist' }, response.status);

  let content = await response.text();
  const baseUrl = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);
  const workerOrigin = new URL(request.url).origin;

  content = content.split('\n').map(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return line;
    const fullUrl = trimmed.startsWith('http') ? trimmed : baseUrl + trimmed;
    return `${workerOrigin}/?url=${encodeURIComponent(fullUrl)}`;
  }).join('\n');

  const headers = new Headers();
  headers.set('Content-Type', 'application/vnd.apple.mpegurl');
  headers.set('Cache-Control', 'public, max-age=60');
  addCorsHeaders(headers);
  return new Response(content, { status: 200, headers });
}

// ─── DIRECT FETCH ────────────────────────────────────────────────────────────

async function fetchDirect(request, targetUrl, parsedTarget, ctx, params) {
  const proxyHeaders = buildHeaders(request, parsedTarget, params);
  const isVideo = isVideoUrl(targetUrl);

  if (request.method === 'HEAD') {
    proxyHeaders.set('Range', 'bytes=0-0');
    const resp = await fetch(targetUrl, { method: 'GET', headers: proxyHeaders, redirect: 'follow' });
    const headers = new Headers();
    if (resp.status === 206 && resp.headers.has('Content-Range')) {
      const match = resp.headers.get('Content-Range').match(/bytes \d+-\d+\/(\d+)/);
      if (match) headers.set('Content-Length', match[1]);
    } else if (resp.headers.has('Content-Length')) {
      headers.set('Content-Length', resp.headers.get('Content-Length'));
    }
    ['Content-Type', 'ETag', 'Last-Modified'].forEach(h => {
      if (resp.headers.has(h)) headers.set(h, resp.headers.get(h));
    });
    headers.set('Accept-Ranges', 'bytes');
    addCorsHeaders(headers);
    return new Response(null, { status: 200, headers });
  }

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: proxyHeaders,
      redirect: 'follow',
      cf: { cacheTtl: isVideo ? 86400 : 3600, cacheEverything: isVideo }
    });

    console.log(`Direct fetch ${targetUrl}: ${response.status}`);

    if ([101, 204, 205, 304].includes(response.status)) {
      const h = new Headers(response.headers);
      addCorsHeaders(h);
      return new Response(null, { status: response.status, headers: h });
    }

    if (response.ok && response.headers.get('content-type')?.includes('text/html')) {
      const text = await response.text();
      if (text.includes("Sorry, you can't view or download")) {
        return jsonResponse({ error: 'Google Drive quota exceeded', tip: 'Add GOOGLE_SERVICE_ACCOUNT env var' }, 429);
      }
      return new Response(text, { status: response.status, headers: { 'Content-Type': 'text/html' } });
    }

    if (!response.ok) {
      if (response.status === 404) return jsonResponse({ error: 'Not found' }, 404);
      if (response.status === 403) return jsonResponse({ error: 'Access forbidden' }, 403);
      if (response.status >= 500) return jsonResponse({ error: 'Origin error', status: response.status }, 502);
      return jsonResponse({ error: `Request failed: ${response.status}` }, response.status);
    }

    const finalHeaders = buildResponseHeaders(response, isVideo);
    if (response.headers.has('Content-Length')) finalHeaders.set('Content-Length', response.headers.get('Content-Length'));

    const filename = extractFilename(response, targetUrl);
    if (filename) finalHeaders.set('Content-Disposition', buildContentDisposition(filename));

    return new Response(response.body, { status: response.status, headers: finalHeaders });
  } catch (error) {
    console.error('Direct fetch error:', error);
    return jsonResponse({ error: 'Failed to fetch URL', details: error.message }, 500);
  }
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function isM3U8Url(url) {
  return /m3u8/i.test(url);
}

function isVideoUrl(url) {
  return /\.(mp4|webm|mkv|avi|mov|flv|m4v|ts|mpg|mpeg|3gp|wmv)(\?|$)/i.test(url);
}

function isVideoMimeType(mimeType) {
  return mimeType?.startsWith('video/') ||
    mimeType === 'application/x-mpegURL' ||
    mimeType === 'application/vnd.apple.mpegurl';
}

function buildGoogleDriveUrl(fileId) {
  return `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t`;
}

function extractGoogleDriveId(url) {
  const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];
  try { return new URL(url).searchParams.get('id'); } catch { return null; }
}

function buildExportUrl(fileId, mimeType) {
  const exportMap = {
    'application/vnd.google-apps.document': 'application/pdf',
    'application/vnd.google-apps.spreadsheet': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.google-apps.presentation': 'application/pdf'
  };
  return `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=${encodeURIComponent(exportMap[mimeType] || 'application/pdf')}`;
}

function buildContentDisposition(fileName) {
  const safe = fileName.replace(/[^\w.\- ]+/g, '_').slice(0, 200);
  return `inline; filename="${safe}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
}

function extractFilename(response, url) {
  const cd = response.headers.get('Content-Disposition');
  if (cd) {
    const match = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
    if (match?.[1]) return match[1].replace(/['"]/g, '');
  }
  try {
    const parts = new URL(url).pathname.split('/');
    const last = parts[parts.length - 1];
    if (last?.includes('.')) return decodeURIComponent(last);
  } catch { }
  return null;
}

function buildHeaders(request, target, params) {
  const headers = new Headers();
  ['Range', 'If-Range', 'If-None-Match', 'If-Modified-Since'].forEach(h => {
    const v = request.headers.get(h);
    if (v) headers.set(h, v);
  });
  headers.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  headers.set('Accept', '*/*');
  headers.set('Connection', 'keep-alive');

  const customReferer = params?.get('referer');
  const customOrigin = params?.get('origin');

  if (target.hostname.includes('drive.google.com') || target.hostname.includes('drive.usercontent.google.com')) {
    headers.set('Referer', customReferer || 'https://drive.google.com/');
    headers.set('Origin', customOrigin || 'https://drive.google.com');
  } else {
    headers.set('Referer', customReferer || `${target.origin}/`);
  }

  return headers;
}

function buildResponseHeaders(response, isVideo) {
  const headers = new Headers(response.headers);
  addCorsHeaders(headers);
  const ct = response.headers.get('Content-Type');
  if (isVideo && (!ct || ct === 'application/octet-stream')) headers.set('Content-Type', 'video/mp4');
  if (!headers.has('Accept-Ranges')) headers.set('Accept-Ranges', 'bytes');
  headers.delete('Content-Encoding');
  headers.delete('Transfer-Encoding');
  headers.set('Cache-Control', isVideo ? 'public, max-age=86400, immutable' : 'public, max-age=3600');
  ['Content-Security-Policy', 'X-Frame-Options', 'Set-Cookie'].forEach(h => headers.delete(h));
  return headers;
}

function validateTargetUrl(url) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return { valid: false, error: 'Invalid protocol', status: 400 };
    const h = parsed.hostname.toLowerCase();
    const blocked = ['localhost', '127.0.0.1', '::1', '0.0.0.0'];
    if (blocked.includes(h)) return { valid: false, error: 'Private IP blocked', status: 403 };
    if (/^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(h)) return { valid: false, error: 'Private IP blocked', status: 403 };
    return { valid: true, url: parsed };
  } catch {
    return { valid: false, error: 'Invalid URL', status: 400 };
  }
}

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, If-Range, If-None-Match, If-Modified-Since',
    'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges, Content-Type, Content-Disposition, ETag, Last-Modified, X-Drive-API, X-Account',
    'Access-Control-Max-Age': '86400'
  };
}

function addCorsHeaders(headers) {
  Object.entries(getCorsHeaders()).forEach(([k, v]) => headers.set(k, v));
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

function base64UrlEncode(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64Decode(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}