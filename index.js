
// Enhanced Proxy with Google Drive Support + Range Polyfill & Stream Splitting
// Improvements: Direct Google Drive integration, iOS playback fix, prevents OOM, referer spoofing
// Version: 1.1 - Fixed uuid, HEAD handling, cache normalization

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error('Worker error:', error);
      return jsonResponse({ error: 'Internal server error', details: error.message }, 500);
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

  // Handle Google Drive file ID directly
  if (fileId && !targetUrl) {
    targetUrl = `https://drive.usercontent.google.com/download` +
                `?id=${fileId}` +
                `&export=download` +
                `&confirm=t` +
                `&uuid=${crypto.randomUUID()}`;
  }

  // Handle Google Drive share URLs
  if (targetUrl && targetUrl.includes('drive.google.com')) {
    const extractedId = extractGoogleDriveId(targetUrl);
    if (extractedId) {
      targetUrl = `https://drive.usercontent.google.com/download` +
                  `?id=${extractedId}` +
                  `&export=download` +
                  `&confirm=t` +
                  `&uuid=${crypto.randomUUID()}`;
    }
  }

  if (!targetUrl) {
    return jsonResponse({ 
      error: 'Missing url or id parameter',
      usage: {
        'Direct URL': '?url=https://example.com/file.mp4',
        'Google Drive ID': '?id=1QQ_v5rA0W_QP8oPSqKq2tmyy66QhZJh0',
        'Google Drive URL': '?url=https://drive.google.com/file/d/FILE_ID/view'
      }
    }, 400);
  }

  // Validate Target
  const validation = validateTargetUrl(targetUrl, env);
  if (!validation.valid) {
    return jsonResponse({ error: validation.error }, validation.status);
  }

  const parsedTarget = validation.url;
  const cache = caches.default;
  const rangeHeader = request.headers.get('Range');

  // 1. Try Cache (Only for non-range requests)
  if (!rangeHeader && request.method === 'GET') {
    const cached = await getCachedResponse(cache, targetUrl, request);
    if (cached) return cached;
  }

  // 2. Fetch from Origin
  return await fetchAndStream(request, targetUrl, parsedTarget, cache, ctx, rangeHeader, url.searchParams);
}

/**
 * Extract Google Drive file ID from various URL formats
 */
function extractGoogleDriveId(url) {
  // /file/d/<ID>/
  const match1 = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
  if (match1) return match1[1];

  // ?id=<ID>
  try {
    const urlObj = new URL(url);
    const id = urlObj.searchParams.get('id');
    if (id) return id;
  } catch (e) {}

  return null;
}

async function fetchAndStream(request, targetUrl, parsedTarget, cache, ctx, rangeHeader, params) {
  const proxyHeaders = buildProxyHeaders(request, parsedTarget, params);
  
  // FIX #2: Handle HEAD requests separately to avoid body issues
  if (request.method === 'HEAD') {
    const headResp = await fetch(targetUrl, {
      method: 'HEAD',
      headers: proxyHeaders,
      redirect: 'follow'
    });

    return new Response(null, {
      status: headResp.status,
      headers: buildResponseHeaders(headResp, null)
    });
  }

  // For Google Drive, add special handling
  if (targetUrl.includes('drive.usercontent.google.com') || targetUrl.includes('drive.google.com')) {
    proxyHeaders.set('Cookie', ''); // Clear cookies for direct download
  }

  const response = await fetch(targetUrl, {
    method: request.method,
    headers: proxyHeaders,
    redirect: 'follow',
    cf: { cacheTtl: 86400, cacheEverything: true }
  });

  // Handle Fetch Errors
  if (!response.ok) {
    if (response.status === 404) return jsonResponse({ error: 'Not found' }, 404);
    if (response.status >= 500) return jsonResponse({ error: 'Origin Error' }, 502);
    // Pass through other errors (like 403)
  }

  let finalResponse = response;
  let finalStatus = response.status;
  let finalHeaders = buildResponseHeaders(response, rangeHeader);

  // 3. THE IOS FIX: Polyfill Range Requests
  // If client sent "Range" but server sent "200 OK", we must slice it manually.
  if (rangeHeader && response.status === 200 && response.body) {
    const parts = rangeHeader.replace(/bytes=/, "").split("-");
    const totalLength = parseInt(response.headers.get('Content-Length') || "0", 10);
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : totalLength - 1;

    if (!isNaN(start) && !isNaN(totalLength) && totalLength > 0) {
      finalStatus = 206; // Partial Content
      finalHeaders.set('Content-Range', `bytes ${start}-${end}/${totalLength}`);
      finalHeaders.set('Content-Length', String(end - start + 1));
      
      // We pipe the body through a slicer
      finalResponse = new Response(response.body.pipeThrough(createSliceStream(start, end)), {
        status: 206,
        statusText: 'Partial Content',
        headers: finalHeaders
      });
    }
  } else {
    // Reconstruct response with new headers
    finalResponse = new Response(response.body, {
      status: finalStatus,
      statusText: response.statusText,
      headers: finalHeaders
    });
  }

  // 4. Memory-Safe Caching (Using Tee)
  // We only cache full 200 OK responses, never partials or manual slices
  if (!rangeHeader && response.status === 200 && finalResponse.body) {
    // FIX #3: Normalize cache key to remove uuid for Drive URLs
    const cacheKey = targetUrl.includes('drive.usercontent.google.com')
      ? targetUrl.replace(/&uuid=[^&]+/, '')
      : targetUrl;

    // split the stream: body1 goes to cache, body2 goes to user
    const [body1, body2] = finalResponse.body.tee();
    
    // Create a copy for the cache
    const responseToCache = new Response(body1, {
      status: finalResponse.status,
      headers: finalHeaders
    });
    
    ctx.waitUntil(cache.put(new Request(cacheKey, { method: 'GET' }), responseToCache));

    // Return the second stream to the user
    return new Response(body2, {
      status: finalResponse.status,
      statusText: finalResponse.statusText,
      headers: finalHeaders
    });
  }

  return finalResponse;
}

// --- Helpers ---

/**
 * Creates a TransformStream that only passes through the requested byte range.
 * Essential for upstreams that don't support Range requests.
 */
function createSliceStream(start, end) {
  let bytesRead = 0;
  return new TransformStream({
    transform(chunk, controller) {
      const chunkEnd = bytesRead + chunk.byteLength;
      if (chunkEnd > start && bytesRead <= end) {
        const sliceStart = Math.max(0, start - bytesRead);
        const sliceEnd = Math.min(chunk.byteLength, end - bytesRead + 1);
        controller.enqueue(chunk.slice(sliceStart, sliceEnd));
      }
      bytesRead += chunk.byteLength;
      if (bytesRead > end) {
        controller.terminate();
      }
    }
  });
}

function buildProxyHeaders(request, parsedTarget, params) {
  const headers = new Headers();
  const allowed = ['Range', 'Accept', 'Accept-Language', 'Accept-Encoding'];
  
  allowed.forEach(h => {
    const value = request.headers.get(h);
    if (value) headers.set(h, value);
  });

  // Allow manual Referer/Origin override via URL params (e.g. ?referer=https://google.com)
  // This is useful for sites with strict hotlink protection
  const customReferer = params.get('referer');
  const customOrigin = params.get('origin');

  headers.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  
  // Smart Referer/Origin handling for Google Drive
  if (parsedTarget.hostname.includes('drive.google.com') || parsedTarget.hostname.includes('drive.usercontent.google.com')) {
    headers.set('Referer', customReferer || 'https://drive.google.com/');
    headers.set('Origin', customOrigin || 'https://drive.google.com');
  } else {
    headers.set('Referer', customReferer || parsedTarget.origin + '/');
    headers.set('Origin', customOrigin || parsedTarget.origin);
  }
  
  return headers;
}

function buildResponseHeaders(response, rangeHeader) {
  const headers = new Headers(response.headers);
  addCorsHeaders(headers);

  // Fix Missing Accept-Ranges
  if (!headers.has('Accept-Ranges')) headers.set('Accept-Ranges', 'bytes');

  // Cache Control
  if (!rangeHeader && response.status === 200) {
    headers.set('Cache-Control', 'public, max-age=86400, immutable');
    headers.set('X-Cache-Status', 'MISS');
  } else {
    // Don't encourage caching of partials/errors
    headers.set('Cache-Control', 'no-cache');
  }

  // Remove security headers that might interfere
  ['Content-Security-Policy', 'X-Frame-Options', 'Set-Cookie'].forEach(h => headers.delete(h));
  
  return headers;
}

function validateTargetUrl(targetUrl, env) {
  try {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, error: 'Invalid protocol', status: 400 };
    }
    // SSRF Check (Simple)
    const hostname = parsed.hostname.toLowerCase();
    const privateHosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0'];
    if (privateHosts.includes(hostname) || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
      return { valid: false, error: 'Private IP not allowed', status: 403 };
    }
    return { valid: true, url: parsed };
  } catch (e) {
    return { valid: false, error: 'Invalid URL', status: 400 };
  }
}

async function getCachedResponse(cache, targetUrl, request) {
  // FIX #3: Normalize cache key when checking cache too
  const cacheKey = targetUrl.includes('drive.usercontent.google.com')
    ? targetUrl.replace(/&uuid=[^&]+/, '')
    : targetUrl;

  const response = await cache.match(new Request(cacheKey, { method: 'GET' }));
  if (!response) return null;

  const headers = new Headers(response.headers);
  headers.set('X-Cache-Status', 'HIT');
  addCorsHeaders(headers);

  return new Response(response.body, {
    status: response.status,
    headers: headers
  });
}

function getCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, If-Match, If-None-Match',
    'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length, Content-Type',
    'Access-Control-Max-Age': '86400',
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
