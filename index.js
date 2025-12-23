// Google Drive Proxy v3.3 - Production Final
// ✅ All critical issues fixed ✅ Token caching ✅ Proper metadata cache ✅ No HEAD lies

export default {
  async fetch(request, env, ctx) {
    try {
        const url = new URL(request.url);
if (url.pathname === '/health') {
  return new Response('OK', {
    status: 200,
    headers: {
      'Content-Type': 'text/plain',
      'Cache-Control': 'no-store'
    }
  });
}
        return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error('Worker error:', error);
      return jsonResponse({ error: 'Server error', details: error.message }, 500);
    }
  }
};

// FIX #2: Token cache (prevents invalid_grant)
const tokenCache = new Map();

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
  const forceDirect = url.searchParams.get('direct') === 'true';
  const authKey = url.searchParams.get('key'); // FIX #6: Optional auth
  
  // FIX #6: Basic auth protection (optional)
  if (env.AUTH_KEY && authKey !== env.AUTH_KEY) {
    return jsonResponse({ 
      error: 'Unauthorized',
      tip: 'Add ?key=YOUR_KEY to the URL'
    }, 401);
  }
  
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
        driveId: '?id=FILE_ID',
        driveIdApi: '?id=FILE_ID&api=true',
        driveIdDirect: '?id=FILE_ID&direct=true',
        withAuth: '?id=FILE_ID&key=YOUR_KEY'
      }
    }, 400);
  }

  // Try API first if we have credentials and a file ID
  if (extractedFileId && !forceDirect && (forceApi || hasServiceAccounts(env))) {
    try {
      return await handleDriveApiRequest(request, extractedFileId, env, ctx);
    } catch (apiError) {
      console.warn('Drive API failed, falling back:', apiError.message);
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

function hasServiceAccounts(env) {
  return env.GOOGLE_SERVICE_ACCOUNT || 
         env.GOOGLE_SERVICE_ACCOUNT_1 || 
         env.GOOGLE_SERVICE_ACCOUNT_2 || 
         env.GOOGLE_SERVICE_ACCOUNT_3;
}

function getAllServiceAccounts(env) {
  const accounts = [];
  
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

async function handleDriveApiRequest(request, fileId, env, ctx) {
  const serviceAccounts = getAllServiceAccounts(env);
  
  if (serviceAccounts.length === 0) {
    throw new Error('No service accounts configured');
  }

  let lastError = null;
  
  for (let i = 0; i < serviceAccounts.length; i++) {
    try {
      const result = await tryServiceAccount(request, fileId, serviceAccounts[i], i, env, ctx);
      if (result) return result;
    } catch (error) {
      console.warn(`Service account ${i} failed:`, error.message);
      lastError = error;
      
      // Don't retry 404 across all accounts
      if (error.message.includes('404') || error.message.includes('not found')) {
        throw error;
      }
      continue;
    }
  }
  
  throw lastError || new Error('All service accounts failed');
}

/**
 * FIX #1: Use caches.default instead of Map for metadata
 * This persists across requests and isolates
 */
async function getFileMetadata(fileId, accessToken) {
  const cacheKey = new Request(`https://metadata.internal/${fileId}`);
  const cache = caches.default;
  
  // Try cache first
  const cached = await cache.match(cacheKey);
  if (cached) {
    return await cached.json();
  }
  
  // Fetch fresh
  const metaUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?fields=size,name,mimeType,md5Checksum,modifiedTime`;
  const metaResp = await fetch(metaUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  
  if (!metaResp.ok) {
    if (metaResp.status === 404) {
      throw new Error('File not found');
    }
    if (metaResp.status === 403) {
      throw new Error('File not accessible with this service account');
    }
    throw new Error(`Metadata fetch failed: ${metaResp.status}`);
  }
  
  const metadata = await metaResp.json();
  
  // Cache for 10 minutes
  await cache.put(
    cacheKey,
    new Response(JSON.stringify(metadata), {
      headers: { 'Cache-Control': 'max-age=600' }
    })
  );
  
  return metadata;
}

async function tryServiceAccount(request, fileId, serviceAccount, accountIndex, env, ctx) {
  // FIX #2: Get cached token
  const accessToken = await getGoogleAccessToken(serviceAccount);
  
  if (!accessToken) {
    throw new Error('Failed to get access token');
  }

  // Get metadata (now properly cached)
  const metadata = await getFileMetadata(fileId, accessToken);
  
  const fileName = metadata.name || 'download';
  const fileSize = parseInt(metadata.size || '0', 10);
  const mimeType = metadata.mimeType || 'application/octet-stream';
  const isGoogleDoc = mimeType.startsWith('application/vnd.google-apps.');
  
  console.log(`File: ${fileName}, Size: ${fileSize}, Type: ${mimeType}, GoogleDoc: ${isGoogleDoc}`);
  
  const rangeHeader = request.headers.get('Range');
  
  // HEAD request
  if (request.method === 'HEAD') {
    const headers = new Headers();
    
    // FIX #3: Don't trust metadata size for Google Docs
    if (!isGoogleDoc && fileSize > 0) {
      headers.set('Content-Length', String(fileSize));
    }
    
    headers.set('Content-Type', isGoogleDoc ? 'application/pdf' : mimeType);
    headers.set('Content-Disposition', buildContentDisposition(fileName));
    
    // FIX #5: Disable ranges for Google Docs
    if (isGoogleDoc) {
      headers.set('Accept-Ranges', 'none');
    } else {
      headers.set('Accept-Ranges', 'bytes');
    }
    
    headers.set('X-Drive-API', 'true');
    headers.set('X-Service-Account', String(accountIndex));
    
    if (metadata.md5Checksum) {
      headers.set('ETag', `"${metadata.md5Checksum}"`);
    }
    
    addCorsHeaders(headers);
    return new Response(null, { status: 200, headers });
  }

  // GET request - setup download URL
  let downloadUrl;
  let exportMimeType = null;
  
  if (isGoogleDoc) {
    const exportMap = {
      'application/vnd.google-apps.document': 'application/pdf',
      'application/vnd.google-apps.spreadsheet': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.google-apps.presentation': 'application/pdf',
      'application/vnd.google-apps.drawing': 'application/pdf'
    };
    
    exportMimeType = exportMap[mimeType] || 'application/pdf';
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=${encodeURIComponent(exportMimeType)}`;
  } else {
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
  }

  const downloadHeaders = new Headers({
    'Authorization': `Bearer ${accessToken}`
  });
  
  // FIX #5: Don't send Range for Google Docs (unsupported)
  if (rangeHeader && !isGoogleDoc) {
    downloadHeaders.set('Range', rangeHeader);
  }

  const response = await fetch(downloadUrl, {
    method: 'GET',
    headers: downloadHeaders
  });

  if (!response.ok) {
    throw new Error(`Download failed: ${response.status}`);
  }

  // Origin returned 206 - pass through directly
  if (response.status === 206) {
    const finalHeaders = new Headers();
    
    ['Content-Type', 'Content-Range', 'Content-Length', 'ETag', 'Last-Modified'].forEach(h => {
      if (response.headers.has(h)) {
        finalHeaders.set(h, response.headers.get(h));
      }
    });
    
    finalHeaders.set('Content-Disposition', buildContentDisposition(fileName));
    finalHeaders.set('Accept-Ranges', 'bytes');
    finalHeaders.set('X-Drive-API', 'true');
    finalHeaders.set('X-Service-Account', String(accountIndex));
    finalHeaders.set('Cache-Control', 'public, max-age=3600');
    addCorsHeaders(finalHeaders);
    
    return new Response(response.body, { status: 206, headers: finalHeaders });
  }

  // Full response - build headers
  const finalHeaders = new Headers();
  finalHeaders.set('Content-Type', exportMimeType || mimeType);
  finalHeaders.set('Content-Disposition', buildContentDisposition(fileName));
  
  // FIX #5: Set proper Accept-Ranges
  if (isGoogleDoc) {
    finalHeaders.set('Accept-Ranges', 'none');
  } else {
    finalHeaders.set('Accept-Ranges', 'bytes');
  }
  
  finalHeaders.set('X-Drive-API', 'true');
  finalHeaders.set('X-Service-Account', String(accountIndex));
  finalHeaders.set('Cache-Control', 'public, max-age=3600');
  
  if (metadata.md5Checksum && !isGoogleDoc) {
    finalHeaders.set('ETag', `"${metadata.md5Checksum}"`);
  }
  if (metadata.modifiedTime) {
    finalHeaders.set('Last-Modified', new Date(metadata.modifiedTime).toUTCString());
  }
  
  addCorsHeaders(finalHeaders);
  
  // Buffer small non-Doc files for guaranteed Content-Length
  const shouldBuffer = !rangeHeader && !isGoogleDoc && fileSize > 0 && fileSize < 200 * 1024 * 1024;
  
  if (shouldBuffer) {
    const buffer = await response.arrayBuffer();
    finalHeaders.set('Content-Length', String(buffer.byteLength));
    
    return new Response(buffer, { status: 200, headers: finalHeaders });
  }
  
  // FIX #3: Only set Content-Length when we're certain
  // For Google Docs: size is unknown until export completes
  // For large files: trust the response header
  if (response.headers.has('Content-Length')) {
    finalHeaders.set('Content-Length', response.headers.get('Content-Length'));
  } else if (!isGoogleDoc && fileSize > 0) {
    // Only for regular files with known size
    finalHeaders.set('Content-Length', String(fileSize));
  }

  return new Response(response.body, { status: 200, headers: finalHeaders });
}

function buildContentDisposition(fileName) {
  const safeAscii = fileName
    .replace(/[^\w.\- ]+/g, '_')
    .slice(0, 200);
  
  return `attachment; filename="${safeAscii}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
}

/**
 * FIX #2: Token caching to prevent invalid_grant
 * Tokens valid for ~1 hour, cache for 55 minutes
 */
async function getGoogleAccessToken(serviceAccount) {
  const email = serviceAccount.client_email;
  const cached = tokenCache.get(email);
  
  // Return cached token if still valid (5 min buffer)
  if (cached && cached.expiry > Date.now() + 300000) {
    return cached.token;
  }
  
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwtHeader = { alg: 'RS256', typ: 'JWT' };
    
    const jwtClaimSet = {
      iss: email,
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
    
    // Cache token
    tokenCache.set(email, {
      token: tokenData.access_token,
      expiry: Date.now() + (tokenData.expires_in || 3600) * 1000
    });
    
    // Cleanup old tokens (keep last 100)
    if (tokenCache.size > 100) {
      const firstKey = tokenCache.keys().next().value;
      tokenCache.delete(firstKey);
    }
    
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
  return `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t`;
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

/**
 * FIX #4: Don't trust HEAD - use GET Range 0-0 instead
 */
async function fetchOptimized(request, targetUrl, parsedTarget, cache, ctx, rangeHeader, params) {
  const proxyHeaders = buildMobileHeaders(request, parsedTarget, params);
  
  // FIX #4: Replace HEAD with GET Range 0-0 for reliability
  if (request.method === 'HEAD') {
    proxyHeaders.set('Range', 'bytes=0-0');
    
    const resp = await fetch(targetUrl, { 
      method: 'GET',
      headers: proxyHeaders,
      redirect: 'follow'
    });
    
    const headers = buildResponseHeaders(resp, null);
    
    // Extract actual size from Content-Range if present
    if (resp.status === 206 && resp.headers.has('Content-Range')) {
      const range = resp.headers.get('Content-Range');
      const match = range.match(/bytes \d+-\d+\/(\d+)/);
      if (match) {
        headers.set('Content-Length', match[1]);
      }
    }
    
    return new Response(null, { status: 200, headers });
  }

  const response = await fetch(targetUrl, {
    method: 'GET',
    headers: proxyHeaders,
    redirect: 'follow',
    cf: { cacheTtl: 3600, cacheEverything: true }
  });

  // Detect quota error
  if (response.ok && response.headers.get('content-type')?.includes('text/html')) {
    const text = await response.text();
    if (text.includes("Sorry, you can't view or download")) {
      return jsonResponse({
        error: 'Google Drive quota exceeded',
        message: 'Direct download quota exceeded. Try ?api=true',
        tip: 'Configure service accounts to bypass this limit'
      }, 429);
    }
  }

  if (!response.ok) {
    if (response.status === 404) return jsonResponse({ error: 'Not found' }, 404);
    if (response.status >= 500) return jsonResponse({ error: 'Origin error' }, 502);
  }

  // Origin returned 206 - pass through
  if (response.status === 206) {
    const finalHeaders = buildResponseHeaders(response, rangeHeader);
    return new Response(response.body, { status: 206, headers: finalHeaders });
  }

  const finalHeaders = buildResponseHeaders(response, rangeHeader);
  
  // FIX #3: Only trust Content-Length if present
  if (response.headers.has('Content-Length')) {
    finalHeaders.set('Content-Length', response.headers.get('Content-Length'));
  }
  
  // Add Content-Disposition if missing
  if (!finalHeaders.has('Content-Disposition')) {
    const filename = extractFilenameFromHeaders(response) || extractFilenameFromUrl(targetUrl);
    if (filename) {
      finalHeaders.set('Content-Disposition', buildContentDisposition(filename));
    }
  }
  
  // Cache full responses only
  if (!rangeHeader && response.status === 200 && response.body) {
    const cacheKey = new Request(targetUrl, { method: 'GET' });
    const [cacheStream, clientStream] = response.body.tee();
    
    ctx.waitUntil(
      cache.put(cacheKey, new Response(cacheStream, { status: 200, headers: finalHeaders }))
    );
    
    return new Response(clientStream, { status: 200, headers: finalHeaders });
  }

  // Handle range request on full response
  if (rangeHeader && response.status === 200 && response.body) {
    return handleRangeRequest(response, rangeHeader, finalHeaders);
  }

  return new Response(response.body, { status: response.status, headers: finalHeaders });
}

function extractFilenameFromHeaders(response) {
  const cd = response.headers.get('Content-Disposition');
  if (cd) {
    const match = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
    if (match && match[1]) {
      return match[1].replace(/['"]/g, '');
    }
  }
  return null;
}

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

/**
 * Handle range request with proper 416 responses
 */
function handleRangeRequest(response, rangeHeader, finalHeaders) {
  const rangeMatch = rangeHeader.match(/bytes=(\d*)-(\d*)/);
  if (!rangeMatch) {
    return new Response(response.body, { status: 200, headers: finalHeaders });
  }

  const [, startStr, endStr] = rangeMatch;
  const start = parseInt(startStr, 10);
  const contentLength = parseInt(response.headers.get('Content-Length') || '0', 10);
  const end = endStr ? parseInt(endStr, 10) : contentLength - 1;

  // Return 416 for invalid range
  if (isNaN(start) || start < 0 || start >= contentLength || contentLength === 0) {
    return new Response('Range Not Satisfiable', { 
      status: 416,
      headers: {
        'Content-Range': `bytes */${contentLength}`,
        'Access-Control-Allow-Origin': '*'
      }
    });
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
    headers.set('Cache-Control', 'public, max-age=3600');
    headers.set('X-Cache-Status', 'MISS');
  } else {
    headers.set('Cache-Control', 'no-cache');
  }

  ['Content-Security-Policy', 'X-Frame-Options', 'Set-Cookie'].forEach(h => headers.delete(h));
  
  return headers;
}

async function getCachedResponse(cache, targetUrl) {
  const cached = await cache.match(new Request(targetUrl, { method: 'GET' }));
  
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
