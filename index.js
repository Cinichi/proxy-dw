// Google Drive Proxy v3.1 - Multi-Account + Proper Filename/Size Headers
// Features: Multiple service accounts, proper Content-Disposition, Content-Length

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error('Worker error:', error);
      return jsonResponse({ error: 'Server error', details: error.message }, 500);
    }
  }
};

async function handleRequest(request, env, ctx) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: getCorsHeaders() });
  }
  
  if (!['GET', 'HEAD'].includes(request.method)) {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }

  const url = new URL(request.url);
  let targetUrl = url.searchParams.get('url');
  const fileId = url.searchParams.get('id');
  const forceApi = url.searchParams.get('api') === 'true';
  
  // Extract file ID
  let extractedFileId = fileId;
  if (!extractedFileId && targetUrl) {
    if (targetUrl.includes('drive.google.com')) {
      extractedFileId = extractGoogleDriveId(targetUrl);
    }
  }
  
  if (!targetUrl && !extractedFileId) {
    return jsonResponse({ 
      error: 'Missing url or id parameter', 
      examples: {
        driveId: '?id=1QQ_v5rA0W_QP8oPSqKq2tmyy66QhZJh0',
        driveIdApi: '?id=FILE_ID&api=true',
        driveUrl: '?url=https://drive.google.com/file/d/ID/view',
        directUrl: '?url=https://example.com/video.mp4'
      }
    }, 400);
  }

  // Try API first if we have credentials and a file ID
  if (extractedFileId && (forceApi || hasServiceAccounts(env))) {
    try {
      return await handleDriveApiRequest(request, extractedFileId, env, ctx);
    } catch (apiError) {
      console.warn('Drive API failed, falling back:', apiError.message);
      // Fall through to direct download
    }
  }

  // Build target URL for direct download
  if (extractedFileId && !targetUrl) {
    targetUrl = buildGoogleDriveUrl(extractedFileId);
  }

  if (!targetUrl) {
    return jsonResponse({ error: 'Could not determine target URL' }, 400);
  }

  const validation = validateTargetUrl(targetUrl);
  if (!validation.valid) {
    return jsonResponse({ error: validation.error }, validation.status);
  }

  const cache = caches.default;
  const rangeHeader = request.headers.get('Range');
  
  if (!rangeHeader && request.method === 'GET') {
    const cached = await getCachedResponse(cache, targetUrl);
    if (cached) return cached;
  }

  return await fetchOptimized(request, targetUrl, validation.url, cache, ctx, rangeHeader, url.searchParams);
}

/**
 * Check if any service accounts are configured
 */
function hasServiceAccounts(env) {
  return env.GOOGLE_SERVICE_ACCOUNT || 
         env.GOOGLE_SERVICE_ACCOUNT_1 || 
         env.GOOGLE_SERVICE_ACCOUNT_2 || 
         env.GOOGLE_SERVICE_ACCOUNT_3;
}

/**
 * Get all configured service accounts
 */
function getAllServiceAccounts(env) {
  const accounts = [];
  
  // Support multiple service accounts (up to 10)
  for (let i = 0; i <= 10; i++) {
    const key = i === 0 ? 'GOOGLE_SERVICE_ACCOUNT' : `GOOGLE_SERVICE_ACCOUNT_${i}`;
    if (env[key]) {
      try {
        accounts.push(JSON.parse(env[key]));
      } catch (e) {
        console.error(`Invalid JSON in ${key}:`, e);
      }
    }
  }
  
  return accounts;
}

/**
 * Handle request using Google Drive API with multi-account support
 */
async function handleDriveApiRequest(request, fileId, env, ctx) {
  const serviceAccounts = getAllServiceAccounts(env);
  
  if (serviceAccounts.length === 0) {
    throw new Error('No service accounts configured');
  }

  let lastError = null;
  
  // Try each service account until one works
  for (let i = 0; i < serviceAccounts.length; i++) {
    try {
      const result = await tryServiceAccount(request, fileId, serviceAccounts[i], i);
      if (result) return result;
    } catch (error) {
      console.warn(`Service account ${i} failed:`, error.message);
      lastError = error;
      continue;
    }
  }
  
  // All accounts failed
  throw lastError || new Error('All service accounts failed');
}

/**
 * Try downloading with a specific service account
 */
async function tryServiceAccount(request, fileId, serviceAccount, accountIndex) {
  const accessToken = await getGoogleAccessToken(serviceAccount);
  
  if (!accessToken) {
    throw new Error('Failed to get access token');
  }

  const rangeHeader = request.headers.get('Range');
  
  // Get file metadata first (for filename and size)
  const metaUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?fields=size,name,mimeType`;
  const metaResp = await fetch(metaUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  
  if (!metaResp.ok) {
    if (metaResp.status === 404 || metaResp.status === 403) {
      throw new Error(`File not accessible with account ${accountIndex}`);
    }
    throw new Error(`Metadata fetch failed: ${metaResp.status}`);
  }
  
  const metadata = await metaResp.json();
  const fileName = metadata.name || 'download';
  const fileSize = metadata.size || '0';
  const mimeType = metadata.mimeType || 'application/octet-stream';
  
  // HEAD request - return metadata
  if (request.method === 'HEAD') {
    const headers = new Headers();
    headers.set('Content-Length', fileSize);
    headers.set('Content-Type', mimeType);
    headers.set('Content-Disposition', `attachment; filename="${encodeFileName(fileName)}"`);
    headers.set('Accept-Ranges', 'bytes');
    headers.set('X-Drive-API', 'true');
    headers.set('X-Service-Account', String(accountIndex));
    addCorsHeaders(headers);
    
    return new Response(null, { status: 200, headers });
  }

  // GET request - download file
  const downloadUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
  const downloadHeaders = new Headers({
    'Authorization': `Bearer ${accessToken}`
  });
  
  if (rangeHeader) {
    downloadHeaders.set('Range', rangeHeader);
  }

  const response = await fetch(downloadUrl, {
    method: 'GET',
    headers: downloadHeaders
  });

  if (!response.ok) {
    throw new Error(`Download failed: ${response.status}`);
  }

  const finalHeaders = new Headers(response.headers);
  
  // FIX: Set proper filename and content-length
  finalHeaders.set('Content-Disposition', `attachment; filename="${encodeFileName(fileName)}"; filename*=UTF-8''${encodeURIComponent(fileName)}`);
  
  if (!finalHeaders.has('Content-Length')) {
    finalHeaders.set('Content-Length', fileSize);
  }
  
  if (!finalHeaders.has('Content-Type')) {
    finalHeaders.set('Content-Type', mimeType);
  }
  
  finalHeaders.set('X-Drive-API', 'true');
  finalHeaders.set('X-Service-Account', String(accountIndex));
  finalHeaders.set('Cache-Control', 'public, max-age=3600');
  addCorsHeaders(finalHeaders);
  
  if (!finalHeaders.has('Accept-Ranges')) {
    finalHeaders.set('Accept-Ranges', 'bytes');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: finalHeaders
  });
}

/**
 * Encode filename for Content-Disposition header (RFC 5987)
 */
function encodeFileName(fileName) {
  // Remove or replace problematic characters
  return fileName
    .replace(/["\\\r\n]/g, '') // Remove quotes, backslashes, newlines
    .replace(/[^\x20-\x7E]/g, '_'); // Replace non-ASCII with underscore for simple encoding
}

/**
 * Get Google OAuth2 access token
 */
async function getGoogleAccessToken(serviceAccount) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwtHeader = { alg: 'RS256', typ: 'JWT' };
    
    const jwtClaimSet = {
      iss: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/drive.readonly',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now
    };

    const encodedHeader = base64UrlEncode(JSON.stringify(jwtHeader));
    const encodedClaimSet = base64UrlEncode(JSON.stringify(jwtClaimSet));
    const signatureInput = `${encodedHeader}.${encodedClaimSet}`;
    
    const privateKey = await importPrivateKey(serviceAccount.private_key);
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      privateKey,
      new TextEncoder().encode(signatureInput)
    );
    
    const encodedSignature = base64UrlEncode(signature);
    const jwt = `${signatureInput}.${encodedSignature}`;
    
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });
    
    if (!tokenResponse.ok) {
      throw new Error(`Token exchange failed: ${tokenResponse.status}`);
    }
    
    const tokenData = await tokenResponse.json();
    return tokenData.access_token;
  } catch (error) {
    console.error('Access token error:', error);
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
    'pkcs8',
    binaryKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

function base64UrlEncode(data) {
  const bytes = typeof data === 'string' 
    ? new TextEncoder().encode(data)
    : new Uint8Array(data);
  
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64Decode(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function buildGoogleDriveUrl(fileId) {
  const uuid = deterministicUUID(fileId);
  return `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t&uuid=${uuid}`;
}

function deterministicUUID(fileId) {
  const encoded = btoa(fileId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8);
  return `${encoded.slice(0, 4)}-${encoded.slice(4, 8)}`;
}

function extractGoogleDriveId(url) {
  const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];
  
  try {
    return new URL(url).searchParams.get('id');
  } catch {
    return null;
  }
}

async function fetchOptimized(request, targetUrl, parsedTarget, cache, ctx, rangeHeader, params) {
  const proxyHeaders = buildMobileHeaders(request, parsedTarget, params);
  
  if (request.method === 'HEAD') {
    const resp = await fetch(targetUrl, { 
      method: 'HEAD', 
      headers: proxyHeaders,
      redirect: 'follow'
    });
    
    return new Response(null, { 
      status: resp.status, 
      headers: buildResponseHeaders(resp, null) 
    });
  }

  const response = await fetch(targetUrl, {
    method: 'GET',
    headers: proxyHeaders,
    redirect: 'follow',
    cf: { cacheTtl: 86400, cacheEverything: true }
  });

  // Detect quota error
  if (response.ok && response.headers.get('content-type')?.includes('text/html')) {
    const text = await response.text();
    if (text.includes("Sorry, you can't view or download")) {
      return jsonResponse({
        error: 'Google Drive quota exceeded',
        message: 'This file has been downloaded too many times.',
        solutions: [
          'Add ?api=true to use API (if configured)',
          'Configure multiple service accounts for load balancing',
          'Make a copy to your own Drive',
          'Wait 24 hours'
        ]
      }, 429);
    }
  }

  if (!response.ok) {
    if (response.status === 404) return jsonResponse({ error: 'Not found' }, 404);
    if (response.status >= 500) return jsonResponse({ error: 'Origin error' }, 502);
  }

  const finalHeaders = buildResponseHeaders(response, rangeHeader);
  
  // FIX: Try to extract filename from Content-Disposition or URL
  if (!finalHeaders.has('Content-Disposition')) {
    const urlFilename = extractFilenameFromUrl(targetUrl);
    if (urlFilename) {
      finalHeaders.set('Content-Disposition', `attachment; filename="${urlFilename}"`);
    }
  }
  
  if (!rangeHeader && response.status === 200 && response.body) {
    const cacheKey = normalizeCacheKey(targetUrl);
    const [cacheStream, clientStream] = response.body.tee();
    
    ctx.waitUntil(
      cache.put(
        new Request(cacheKey, { method: 'GET' }), 
        new Response(cacheStream, { status: 200, headers: finalHeaders })
      )
    );
    
    return new Response(clientStream, { status: 200, headers: finalHeaders });
  }

  if (rangeHeader && response.status === 200 && response.body) {
    return handleRangeRequest(response, rangeHeader, finalHeaders);
  }

  return new Response(response.body, { status: response.status, headers: finalHeaders });
}

/**
 * Extract filename from URL path
 */
function extractFilenameFromUrl(url) {
  try {
    const pathname = new URL(url).pathname;
    const parts = pathname.split('/');
    const lastPart = parts[parts.length - 1];
    if (lastPart && lastPart.includes('.')) {
      return decodeURIComponent(lastPart);
    }
  } catch (e) {}
  return null;
}

function handleRangeRequest(response, rangeHeader, finalHeaders) {
  const rangeMatch = rangeHeader.match(/bytes=(\d*)-(\d*)/);
  if (!rangeMatch) {
    return new Response(response.body, { status: 200, headers: finalHeaders });
  }

  const [, startStr, endStr] = rangeMatch;
  const start = parseInt(startStr, 10);
  const contentLength = parseInt(response.headers.get('Content-Length') || '0', 10);
  const end = endStr ? parseInt(endStr, 10) : contentLength - 1;

  if (isNaN(start) || start < 0 || start >= contentLength || contentLength === 0) {
    return new Response(response.body, { status: 200, headers: finalHeaders });
  }

  finalHeaders.set('Content-Range', `bytes ${start}-${end}/${contentLength}`);
  finalHeaders.set('Content-Length', String(end - start + 1));
  
  return new Response(
    response.body.pipeThrough(createEfficientSliceStream(start, end)),
    { status: 206, statusText: 'Partial Content', headers: finalHeaders }
  );
}

function createEfficientSliceStream(start, end) {
  let bytesRead = 0;
  
  return new TransformStream({
    transform(chunk, controller) {
      const chunkStart = bytesRead;
      const chunkEnd = bytesRead + chunk.byteLength;
      
      if (chunkEnd <= start) {
        bytesRead += chunk.byteLength;
        return;
      }
      
      if (chunkStart > end) {
        controller.terminate();
        return;
      }
      
      const sliceStart = Math.max(0, start - chunkStart);
      const sliceEnd = Math.min(chunk.byteLength, end - chunkStart + 1);
      
      controller.enqueue(chunk.slice(sliceStart, sliceEnd));
      bytesRead += chunk.byteLength;
      
      if (bytesRead > end) {
        controller.terminate();
      }
    }
  });
}

function buildMobileHeaders(request, target, params) {
  const headers = new Headers();
  
  const allowedHeaders = ['Range', 'If-Range', 'If-None-Match', 'If-Modified-Since'];
  allowedHeaders.forEach(h => {
    const value = request.headers.get(h);
    if (value) headers.set(h, value);
  });
  
  headers.set('User-Agent', 
    request.headers.get('User-Agent') || 
    'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36'
  );
  
  headers.set('Accept', '*/*');
  headers.set('Accept-Encoding', 'identity');
  headers.set('Connection', 'keep-alive');
  
  const customReferer = params.get('referer');
  const customOrigin = params.get('origin');
  
  if (target.hostname.includes('drive.google.com') || target.hostname.includes('drive.usercontent.google.com')) {
    headers.set('Referer', customReferer || 'https://drive.google.com/');
    headers.set('Origin', customOrigin || 'https://drive.google.com');
  } else {
    headers.set('Referer', customReferer || target.origin + '/');
    headers.set('Origin', customOrigin || target.origin);
  }

  return headers;
}

function buildResponseHeaders(response, rangeHeader) {
  const headers = new Headers(response.headers);
  addCorsHeaders(headers);
  
  if (!headers.has('Accept-Ranges')) {
    headers.set('Accept-Ranges', 'bytes');
  }
  
  headers.delete('Content-Encoding');
  
  if (!rangeHeader && response.status === 200) {
    headers.set('Cache-Control', 'public, max-age=86400, immutable');
    headers.set('X-Cache-Status', 'MISS');
  } else {
    headers.set('Cache-Control', 'no-cache');
  }

  ['Content-Security-Policy', 'X-Frame-Options', 'Set-Cookie'].forEach(h => headers.delete(h));
  
  return headers;
}

function normalizeCacheKey(url) {
  return url.replace(/[&?]uuid=[^&]+/, '');
}

async function getCachedResponse(cache, targetUrl) {
  const cacheKey = normalizeCacheKey(targetUrl);
  const cached = await cache.match(new Request(cacheKey, { method: 'GET' }));
  
  if (!cached) return null;
  
  const headers = new Headers(cached.headers);
  headers.set('X-Cache-Status', 'HIT');
  addCorsHeaders(headers);
  
  return new Response(cached.body, { status: cached.status, headers });
}

function validateTargetUrl(url) {
  try {
    const parsed = new URL(url);
    
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, error: 'Invalid protocol', status: 400 };
    }
    
    const hostname = parsed.hostname.toLowerCase();
    const privatePatterns = [
      'localhost', '127.0.0.1', '::1', '0.0.0.0',
      /^192\.168\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./
    ];
    
    for (const pattern of privatePatterns) {
      if (typeof pattern === 'string') {
        if (hostname === pattern) {
          return { valid: false, error: 'Private IP not allowed', status: 403 };
        }
      } else if (pattern.test(hostname)) {
        return { valid: false, error: 'Private IP not allowed', status: 403 };
      }
    }
    
    return { valid: true, url: parsed };
  } catch (e) {
    return { valid: false, error: 'Invalid URL', status: 400 };
  }
}

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, If-Range, If-None-Match, If-Modified-Since',
    'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges, Content-Type, Content-Disposition, ETag, Last-Modified, X-Drive-API, X-Cache-Status, X-Service-Account',
    'Access-Control-Max-Age': '86400'
  };
}

function addCorsHeaders(headers) {
  Object.entries(getCorsHeaders()).forEach(([k, v]) => headers.set(k, v));
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}
