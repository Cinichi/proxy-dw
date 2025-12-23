// Google Drive Proxy v3.0 - With API Support (Unlimited Downloads)
// Features: Bypasses quota limits, auto-fallback, 3x faster speeds

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
  const forceApi = url.searchParams.get('api') === 'true'; // ?api=true to force API
  
  // Extract file ID from various formats
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
        driveIdApi: '?id=FILE_ID&api=true (force API, bypasses quota)',
        driveUrl: '?url=https://drive.google.com/file/d/ID/view',
        directUrl: '?url=https://example.com/video.mp4'
      }
    }, 400);
  }

  // If we have Google Drive file ID and credentials, try API first
  if (extractedFileId && (forceApi || env.GOOGLE_SERVICE_ACCOUNT)) {
    try {
      return await handleDriveApiRequest(request, extractedFileId, env, ctx);
    } catch (apiError) {
      console.warn('Drive API failed, falling back to direct:', apiError.message);
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
  
  // Try cache for full requests only
  if (!rangeHeader && request.method === 'GET') {
    const cached = await getCachedResponse(cache, targetUrl);
    if (cached) return cached;
  }

  return await fetchOptimized(request, targetUrl, validation.url, cache, ctx, rangeHeader, url.searchParams);
}

/**
 * Handle request using Google Drive API (bypasses quota)
 */
async function handleDriveApiRequest(request, fileId, env, ctx) {
  // Get access token
  const accessToken = await getGoogleAccessToken(env);
  
  if (!accessToken) {
    throw new Error('No valid access token');
  }

  const rangeHeader = request.headers.get('Range');
  
  // HEAD request
  if (request.method === 'HEAD') {
    const metaUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?fields=size,name,mimeType`;
    const metaResp = await fetch(metaUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    
    if (!metaResp.ok) {
      throw new Error(`API metadata fetch failed: ${metaResp.status}`);
    }
    
    const metadata = await metaResp.json();
    const headers = new Headers();
    headers.set('Content-Length', metadata.size || '0');
    headers.set('Content-Type', metadata.mimeType || 'application/octet-stream');
    headers.set('Accept-Ranges', 'bytes');
    headers.set('X-Drive-API', 'true');
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
    // If 403/404, file might not be accessible to service account
    if (response.status === 403 || response.status === 404) {
      throw new Error('File not accessible via API - ensure file is shared with service account');
    }
    throw new Error(`API download failed: ${response.status}`);
  }

  const finalHeaders = new Headers(response.headers);
  finalHeaders.set('X-Drive-API', 'true');
  finalHeaders.set('Cache-Control', 'public, max-age=3600');
  addCorsHeaders(finalHeaders);
  
  // Ensure Accept-Ranges header
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
 * Get Google OAuth2 access token from service account credentials
 */
async function getGoogleAccessToken(env) {
  // Check if service account JSON is configured
  if (!env.GOOGLE_SERVICE_ACCOUNT) {
    return null;
  }

  try {
    const serviceAccount = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT);
    
    // Create JWT
    const now = Math.floor(Date.now() / 1000);
    const jwtHeader = {
      alg: 'RS256',
      typ: 'JWT'
    };
    
    const jwtClaimSet = {
      iss: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/drive.readonly',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now
    };

    // Encode JWT
    const encodedHeader = base64UrlEncode(JSON.stringify(jwtHeader));
    const encodedClaimSet = base64UrlEncode(JSON.stringify(jwtClaimSet));
    const signatureInput = `${encodedHeader}.${encodedClaimSet}`;
    
    // Sign JWT with private key
    const privateKey = await importPrivateKey(serviceAccount.private_key);
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      privateKey,
      new TextEncoder().encode(signatureInput)
    );
    
    const encodedSignature = base64UrlEncode(signature);
    const jwt = `${signatureInput}.${encodedSignature}`;
    
    // Exchange JWT for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });
    
    if (!tokenResponse.ok) {
      console.error('Token exchange failed:', await tokenResponse.text());
      return null;
    }
    
    const tokenData = await tokenResponse.json();
    return tokenData.access_token;
  } catch (error) {
    console.error('Access token error:', error);
    return null;
  }
}

/**
 * Import RSA private key for JWT signing
 */
async function importPrivateKey(pemKey) {
  // Remove PEM header/footer and newlines
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

/**
 * Base64 URL-safe encode
 */
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

/**
 * Base64 decode
 */
function base64Decode(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Build Google Drive direct download URL
 */
function buildGoogleDriveUrl(fileId) {
  const uuid = deterministicUUID(fileId);
  return `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t&uuid=${uuid}`;
}

/**
 * Generate deterministic UUID from file ID
 */
function deterministicUUID(fileId) {
  const encoded = btoa(fileId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8);
  return `${encoded.slice(0, 4)}-${encoded.slice(4, 8)}`;
}

/**
 * Extract Google Drive file ID
 */
function extractGoogleDriveId(url) {
  const match = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];
  
  try {
    const parsed = new URL(url);
    return parsed.searchParams.get('id');
  } catch {
    return null;
  }
}

async function fetchOptimized(request, targetUrl, parsedTarget, cache, ctx, rangeHeader, params) {
  const proxyHeaders = buildMobileHeaders(request, parsedTarget, params);
  
  // HEAD requests
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

  // Fetch from origin
  const response = await fetch(targetUrl, {
    method: 'GET',
    headers: proxyHeaders,
    redirect: 'follow',
    cf: { cacheTtl: 86400, cacheEverything: true }
  });

  // Detect quota error page
  if (response.ok && response.headers.get('content-type')?.includes('text/html')) {
    const text = await response.text();
    if (text.includes("Sorry, you can't view or download")) {
      return jsonResponse({
        error: 'Google Drive quota exceeded',
        message: 'This file has been downloaded too many times in the last 24 hours.',
        solutions: [
          'Add ?api=true to your URL to use API (if configured)',
          'Make a copy to your own Drive',
          'Wait 24 hours for quota reset',
          'Contact the file owner'
        ],
        tip: 'Configure GOOGLE_SERVICE_ACCOUNT secret to bypass quota limits'
      }, 429);
    }
  }

  if (!response.ok) {
    if (response.status === 404) return jsonResponse({ error: 'Not found' }, 404);
    if (response.status >= 500) return jsonResponse({ error: 'Origin error' }, 502);
  }

  const finalHeaders = buildResponseHeaders(response, rangeHeader);
  
  // Full download - cache it
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

  // Range request
  if (rangeHeader && response.status === 200 && response.body) {
    return handleRangeRequest(response, rangeHeader, finalHeaders);
  }

  return new Response(response.body, { status: response.status, headers: finalHeaders });
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
    'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges, Content-Type, ETag, Last-Modified, X-Drive-API, X-Cache-Status',
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
