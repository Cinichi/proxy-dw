// Google Drive Proxy v3.6.0 - STREAMING OPTIMIZED
// ✓ HLS/DASH streaming ✓ M3U8 rewriting ✓ Video chunk support ✓ Aggressive caching

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
  
  let extractedFileId = fileId;
  if (!extractedFileId && targetUrl?.includes('drive.google.com')) {
    extractedFileId = extractGoogleDriveId(targetUrl);
  }
  
  if (!targetUrl && !extractedFileId) {
    return jsonResponse({ 
      error: 'Missing url or id parameter', 
      examples: {
        driveId: '?id=FILE_ID',
        video: '?url=https://example.com/video.mp4',
        m3u8: '?url=https://example.com/playlist.m3u8'
      }
    }, 400);
  }

  // API path (fastest with service accounts)
  if (extractedFileId && !forceDirect && (forceApi || hasServiceAccounts(env))) {
    try {
      return await handleDriveApiRequest(request, extractedFileId, env, ctx);
    } catch (apiError) {
      console.warn('API failed:', apiError.message);
    }
  }

  // Direct path
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

  // Check if M3U8 playlist (HLS streaming)
  if (isM3U8Url(targetUrl)) {
    return await handleM3U8Request(request, targetUrl, validation.url, ctx, url.searchParams);
  }

  return await fetchDirect(request, targetUrl, validation.url, ctx, url.searchParams);
}

function isM3U8Url(url) {
  return url.toLowerCase().includes('.m3u8') || url.toLowerCase().includes('m3u8');
}

function isVideoUrl(url) {
  const videoExts = /\.(mp4|webm|mkv|avi|mov|flv|m4v|ts|mpg|mpeg|3gp|wmv)(\?|$)/i;
  return videoExts.test(url);
}

/**
 * Handle M3U8 playlists - rewrite URLs to proxy them
 */
async function handleM3U8Request(request, targetUrl, parsedTarget, ctx, params) {
  const proxyHeaders = buildHeaders(request, parsedTarget, params);
  
  const response = await fetch(targetUrl, {
    method: 'GET',
    headers: proxyHeaders,
    redirect: 'follow',
    cf: { cacheTtl: 60 } // Cache playlists for 1 minute
  });

  if (!response.ok) {
    return jsonResponse({ error: 'Failed to fetch playlist' }, response.status);
  }

  let content = await response.text();
  const baseUrl = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);
  const workerUrl = new URL(request.url).origin;

  // Rewrite relative URLs in M3U8 to proxy through worker
  content = content.split('\n').map(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return line;
    
    // Absolute URL
    if (line.startsWith('http://') || line.startsWith('https://')) {
      return `${workerUrl}/?url=${encodeURIComponent(line)}`;
    }
    
    // Relative URL
    const fullUrl = baseUrl + line;
    return `${workerUrl}/?url=${encodeURIComponent(fullUrl)}`;
  }).join('\n');

  const headers = new Headers();
  headers.set('Content-Type', 'application/vnd.apple.mpegurl');
  headers.set('Cache-Control', 'public, max-age=60');
  addCorsHeaders(headers);

  return new Response(content, { status: 200, headers });
}

function hasServiceAccounts(env) {
  return env.GOOGLE_SERVICE_ACCOUNT || env.GOOGLE_SERVICE_ACCOUNT_1 || env.GOOGLE_SERVICE_ACCOUNT_2;
}

function getAllServiceAccounts(env) {
  const accounts = [];
  for (let i = 0; i <= 10; i++) {
    const key = i === 0 ? 'GOOGLE_SERVICE_ACCOUNT' : `GOOGLE_SERVICE_ACCOUNT_${i}`;
    if (env[key]) {
      try {
        accounts.push(JSON.parse(env[key]));
      } catch (e) {
        console.error(`Invalid JSON in ${key}`);
      }
    }
  }
  return accounts;
}

async function handleDriveApiRequest(request, fileId, env, ctx) {
  const serviceAccounts = getAllServiceAccounts(env);
  if (serviceAccounts.length === 0) throw new Error('No service accounts');

  let lastError = null;
  for (let i = 0; i < serviceAccounts.length; i++) {
    try {
      const result = await tryServiceAccount(request, fileId, serviceAccounts[i], i, ctx);
      if (result) return result;
    } catch (error) {
      console.warn(`Account ${i} failed:`, error.message);
      lastError = error;
      if (error.message.includes('404') || error.message.includes('not found')) throw error;
    }
  }
  throw lastError || new Error('All accounts failed');
}

async function getFileMetadata(fileId, accessToken, ctx) {
  const cache = caches.default;
  const cacheKey = new Request(`https://meta.internal/${fileId}`);
  
  const cached = await cache.match(cacheKey);
  if (cached) return await cached.json();
  
  const metaUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?fields=size,name,mimeType,md5Checksum,modifiedTime`;
  const metaResp = await fetch(metaUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  
  if (!metaResp.ok) {
    if (metaResp.status === 404) throw new Error('File not found');
    if (metaResp.status === 403) throw new Error('File not accessible');
    throw new Error(`Metadata failed: ${metaResp.status}`);
  }
  
  const metadata = await metaResp.json();
  
  const cacheResp = new Response(JSON.stringify(metadata), {
    headers: { 'Cache-Control': 'max-age=600' }
  });
  ctx.waitUntil(cache.put(cacheKey, cacheResp));
  
  return metadata;
}

async function tryServiceAccount(request, fileId, serviceAccount, accountIndex, ctx) {
  const accessToken = await getGoogleAccessToken(serviceAccount, ctx);
  if (!accessToken) throw new Error('No access token');

  const metadata = await getFileMetadata(fileId, accessToken, ctx);
  
  const fileName = metadata.name || 'download';
  const fileSize = parseInt(metadata.size || '0', 10);
  const mimeType = metadata.mimeType || 'application/octet-stream';
  const isGoogleDoc = mimeType.startsWith('application/vnd.google-apps.');
  
  const rangeHeader = request.headers.get('Range');
  
  if (request.method === 'HEAD') {
    const downloadUrl = isGoogleDoc 
      ? buildExportUrl(fileId, mimeType)
      : `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
    
    const headHeaders = new Headers({
      'Authorization': `Bearer ${accessToken}`,
      'Range': 'bytes=0-0'
    });
    
    const headResp = await fetch(downloadUrl, {
      method: 'GET',
      headers: headHeaders
    });
    
    const headers = new Headers();
    
    if (headResp.status === 206 && headResp.headers.has('Content-Range')) {
      const range = headResp.headers.get('Content-Range');
      const match = range.match(/bytes \d+-\d+\/(\d+)/);
      if (match) {
        headers.set('Content-Length', match[1]);
      }
    } else if (!isGoogleDoc && fileSize > 0) {
      headers.set('Content-Length', String(fileSize));
    }
    
    headers.set('Content-Type', isGoogleDoc ? 'application/pdf' : mimeType);
    headers.set('Content-Disposition', buildContentDisposition(fileName));
    headers.set('Accept-Ranges', isGoogleDoc ? 'none' : 'bytes');
    headers.set('X-Drive-API', 'true');
    headers.set('X-Account', String(accountIndex));
    
    if (metadata.md5Checksum && !isGoogleDoc) {
      headers.set('ETag', `"${metadata.md5Checksum}"`);
    }
    if (metadata.modifiedTime) {
      headers.set('Last-Modified', new Date(metadata.modifiedTime).toUTCString());
    }
    
    addCorsHeaders(headers);
    return new Response(null, { status: 200, headers });
  }

  const downloadUrl = isGoogleDoc 
    ? buildExportUrl(fileId, mimeType)
    : `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;

  const downloadHeaders = new Headers({
    'Authorization': `Bearer ${accessToken}`,
    'Connection': 'keep-alive'
  });
  
  if (rangeHeader && !isGoogleDoc) {
    downloadHeaders.set('Range', rangeHeader);
  }

  const response = await fetch(downloadUrl, {
    method: 'GET',
    headers: downloadHeaders,
    cf: { 
      cacheTtl: 86400, // Cache video chunks for 24 hours
      cacheEverything: isVideoMimeType(mimeType)
    }
  });

  if (!response.ok) {
    throw new Error(`Download failed: ${response.status}`);
  }

  // Handle null-body status codes
  if ([101, 204, 205, 304].includes(response.status)) {
    const headers = new Headers(response.headers);
    addCorsHeaders(headers);
    return new Response(null, { status: response.status, headers });
  }

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
    finalHeaders.set('X-Account', String(accountIndex));
    finalHeaders.set('Cache-Control', 'public, max-age=86400, immutable');
    addCorsHeaders(finalHeaders);
    
    return new Response(response.body, { status: 206, headers: finalHeaders });
  }

  const finalHeaders = new Headers();
  finalHeaders.set('Content-Type', response.headers.get('Content-Type') || mimeType);
  finalHeaders.set('Content-Disposition', buildContentDisposition(fileName));
  finalHeaders.set('Accept-Ranges', isGoogleDoc ? 'none' : 'bytes');
  finalHeaders.set('X-Drive-API', 'true');
  finalHeaders.set('X-Account', String(accountIndex));
  finalHeaders.set('Cache-Control', 'public, max-age=86400');
  
  if (response.headers.has('Content-Length')) {
    finalHeaders.set('Content-Length', response.headers.get('Content-Length'));
  } else if (!isGoogleDoc && fileSize > 0) {
    finalHeaders.set('Content-Length', String(fileSize));
  }
  
  if (metadata.md5Checksum && !isGoogleDoc) {
    finalHeaders.set('ETag', `"${metadata.md5Checksum}"`);
  }
  if (metadata.modifiedTime) {
    finalHeaders.set('Last-Modified', new Date(metadata.modifiedTime).toUTCString());
  }
  
  addCorsHeaders(finalHeaders);
  
  return new Response(response.body, { status: 200, headers: finalHeaders });
}

function isVideoMimeType(mimeType) {
  return mimeType && (
    mimeType.startsWith('video/') || 
    mimeType === 'application/x-mpegURL' ||
    mimeType === 'application/vnd.apple.mpegurl'
  );
}

function buildExportUrl(fileId, mimeType) {
  const exportMap = {
    'application/vnd.google-apps.document': 'application/pdf',
    'application/vnd.google-apps.spreadsheet': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.google-apps.presentation': 'application/pdf'
  };
  const exportMimeType = exportMap[mimeType] || 'application/pdf';
  return `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=${encodeURIComponent(exportMimeType)}`;
}

function buildContentDisposition(fileName) {
  const safeAscii = fileName.replace(/[^\w.\- ]+/g, '_').slice(0, 200);
  return `inline; filename="${safeAscii}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
}

async function getGoogleAccessToken(serviceAccount, ctx) {
  const email = serviceAccount.client_email;
  const cache = caches.default;
  const cacheKey = new Request(`https://auth.internal/${btoa(email)}`);
  
  const cached = await cache.match(cacheKey);
  if (cached) {
    return await cached.text();
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
    const token = tokenData.access_token;
    
    const cacheResp = new Response(token, {
      headers: { 'Cache-Control': 'max-age=3000' }
    });
    ctx.waitUntil(cache.put(cacheKey, cacheResp));
    
    return token;
  } catch (error) {
    console.error('Token error:', error);
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
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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

async function fetchDirect(request, targetUrl, parsedTarget, ctx, params) {
  const proxyHeaders = buildHeaders(request, parsedTarget, params);
  
  if (request.method === 'HEAD') {
    proxyHeaders.set('Range', 'bytes=0-0');
    const resp = await fetch(targetUrl, { 
      method: 'GET',
      headers: proxyHeaders,
      redirect: 'follow'
    });
    
    const headers = new Headers();
    if (resp.status === 206 && resp.headers.has('Content-Range')) {
      const range = resp.headers.get('Content-Range');
      const match = range.match(/bytes \d+-\d+\/(\d+)/);
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

  const isVideo = isVideoUrl(targetUrl);
  
  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: proxyHeaders,
      redirect: 'follow',
      cf: {
        cacheTtl: isVideo ? 86400 : 3600,
        cacheEverything: isVideo
      }
    });

    // Log for debugging
    console.log(`Fetch ${targetUrl}: ${response.status}`);
    
    // Handle null-body status codes (101, 204, 205, 304)
    if ([101, 204, 205, 304].includes(response.status)) {
      const headers = new Headers(response.headers);
      addCorsHeaders(headers);
      return new Response(null, { status: response.status, headers });
    }
    
    if (response.ok && response.headers.get('content-type')?.includes('text/html')) {
      const text = await response.text();
      if (text.includes("Sorry, you can't view or download")) {
        return jsonResponse({
          error: 'Quota exceeded',
          tip: 'Use ?api=true with service accounts'
        }, 429);
      }
      // If we got HTML instead of video, return it as-is for debugging
      return new Response(text, {
        status: response.status,
        headers: { 'Content-Type': 'text/html' }
      });
    }

    if (!response.ok) {
      console.error(`Failed to fetch: ${response.status} ${response.statusText}`);
      if (response.status === 404) return jsonResponse({ error: 'Not found', url: targetUrl }, 404);
      if (response.status === 403) return jsonResponse({ error: 'Access forbidden', url: targetUrl }, 403);
      if (response.status >= 500) return jsonResponse({ error: 'Origin server error', status: response.status }, 502);
      return jsonResponse({ error: `Request failed with status ${response.status}` }, response.status);
    }

    const finalHeaders = buildResponseHeaders(response, isVideo);
    
    // Ensure Content-Type is set for videos
    if (isVideo && !finalHeaders.has('Content-Type')) {
      finalHeaders.set('Content-Type', 'video/mp4');
    }
    
    if (response.headers.has('Content-Length')) {
      finalHeaders.set('Content-Length', response.headers.get('Content-Length'));
    }
    
    const filename = extractFilename(response, targetUrl);
    if (filename && !finalHeaders.has('Content-Disposition')) {
      finalHeaders.set('Content-Disposition', buildContentDisposition(filename));
    }
    
    return new Response(response.body, { 
      status: response.status, 
      headers: finalHeaders 
    });
  } catch (error) {
    console.error('Fetch error:', error);
    return jsonResponse({ 
      error: 'Failed to fetch URL', 
      details: error.message,
      url: targetUrl 
    }, 500);
  }
}

function extractFilename(response, url) {
  const cd = response.headers.get('Content-Disposition');
  if (cd) {
    const match = cd.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
    if (match && match[1]) return match[1].replace(/['"]/g, '');
  }
  try {
    const pathname = new URL(url).pathname;
    const parts = pathname.split('/');
    const lastPart = parts[parts.length - 1];
    if (lastPart && lastPart.includes('.')) return decodeURIComponent(lastPart);
  } catch (e) {}
  return null;
}

function buildHeaders(request, target, params) {
  const headers = new Headers();
  
  // Forward range headers
  ['Range', 'If-Range', 'If-None-Match', 'If-Modified-Since'].forEach(h => {
    const value = request.headers.get(h);
    if (value) headers.set(h, value);
  });
  
  // Use a real browser user agent
  headers.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  headers.set('Accept', '*/*');
  headers.set('Connection', 'keep-alive');
  
  // Don't set Accept-Encoding to avoid compression issues
  
  const customReferer = params.get('referer');
  const customOrigin = params.get('origin');
  
  // Special handling for watchpeopledie.tv CDN
  if (target.hostname.includes('watchpeopledie.tv')) {
    headers.set('Referer', customReferer || 'https://watchpeopledie.tv/');
    // Don't set Origin for CDN - may cause 403
  } else if (target.hostname.includes('drive.google.com') || target.hostname.includes('drive.usercontent.google.com')) {
    headers.set('Referer', customReferer || 'https://drive.google.com/');
    headers.set('Origin', customOrigin || 'https://drive.google.com');
  } else {
    headers.set('Referer', customReferer || target.origin + '/');
  }
  
  return headers;
}

function buildResponseHeaders(response, isVideo) {
  const headers = new Headers(response.headers);
  addCorsHeaders(headers);
  
  // Force correct video MIME type for browser compatibility
  const contentType = response.headers.get('Content-Type');
  if (isVideo && (!contentType || contentType === 'application/octet-stream')) {
    headers.set('Content-Type', 'video/mp4');
  }
  
  if (!headers.has('Accept-Ranges')) headers.set('Accept-Ranges', 'bytes');
  
  // Remove headers that might break streaming
  headers.delete('Content-Encoding');
  headers.delete('Transfer-Encoding');
  
  // Aggressive caching for video content
  if (isVideo) {
    headers.set('Cache-Control', 'public, max-age=86400, immutable');
  } else {
    headers.set('Cache-Control', 'public, max-age=3600');
  }
  
  ['Content-Security-Policy', 'X-Frame-Options', 'Set-Cookie'].forEach(h => headers.delete(h));
  return headers;
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
        if (hostname === pattern) return { valid: false, error: 'Private IP blocked', status: 403 };
      } else if (pattern.test(hostname)) {
        return { valid: false, error: 'Private IP blocked', status: 403 };
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
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}
