// Enhanced Proxy with Range Polyfill & Stream Splitting
// Improvements: Fixes iOS playback issues, prevents OOM on large files, adds referer spoofing

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
  const targetUrl = url.searchParams.get('url');

  if (!targetUrl) {
    return jsonResponse({ error: 'Missing url parameter' }, 400);
  }

  // Validate Target
  const validation = validateTargetUrl(targetUrl, env);
  if (!validation.valid) {
    return jsonResponse({ error: validation.error }, validation.status);
  }

  const parsedTarget = validation.url;
  const cache = caches.default;
  const rangeHeader = request.headers.get('Range');

  // 1. Try Cache (Only for non-range requests usually, or exact matches)
  // Note: Caching range requests is complex. We mostly focus on caching full files here.
  if (!rangeHeader) {
    const cached = await getCachedResponse(cache, targetUrl, request);
    if (cached) return cached;
  }

  // 2. Fetch from Origin
  return await fetchAndStream(request, targetUrl, parsedTarget, cache, ctx, rangeHeader, url.searchParams);
}

async function fetchAndStream(request, targetUrl, parsedTarget, cache, ctx, rangeHeader, params) {
  const proxyHeaders = buildProxyHeaders(request, parsedTarget, params);
  
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
  if (rangeHeader && response.status === 200) {
    const parts = rangeHeader.replace(/bytes=/, "").split("-");
    const totalLength = parseInt(response.headers.get('Content-Length') || "0", 10);
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : totalLength - 1;

    if (!isNaN(start) && !isNaN(totalLength)) {
      finalStatus = 206; // Partial Content
      finalHeaders.set('Content-Range', `bytes ${start}-${end}/${totalLength}`);
      finalHeaders.set('Content-Length', (end - start) + 1);
      
      // We pipe the body through a slicer
      if (response.body) {
        finalResponse = new Response(response.body.pipeThrough(createSliceStream(start, end)), {
            status: 206,
            statusText: 'Partial Content',
            headers: finalHeaders
        });
      }
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
  if (!rangeHeader && response.status === 200) {
    // split the stream: body1 goes to cache, body2 goes to user
    const [body1, body2] = finalResponse.body.tee();
    
    // Create a copy for the cache
    const responseToCache = new Response(body1, {
        status: finalResponse.status,
        headers: finalHeaders
    });
    
    ctx.waitUntil(cache.put(new Request(targetUrl, { method: 'GET' }), responseToCache));

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
    if (request.headers.get(h)) headers.set(h, request.headers.get(h));
  });

  // Allow manual Referer/Origin override via URL params (e.g. ?referer=https://google.com)
  // This is useful for sites with strict hotlink protection
  const customReferer = params.get('referer');
  const customOrigin = params.get('origin');

  headers.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
  headers.set('Referer', customReferer || parsedTarget.origin + '/');
  headers.set('Origin', customOrigin || parsedTarget.origin);
  
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
    if (['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)) {
        return { valid: false, error: 'Private IP not allowed', status: 403 };
    }
    return { valid: true, url: parsed };
  } catch (e) {
    return { valid: false, error: 'Invalid URL', status: 400 };
  }
}

async function getCachedResponse(cache, targetUrl, request) {
  // Simple cache match for non-range requests
  const response = await cache.match(new Request(targetUrl, { method: 'GET' }));
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
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    }
  });
}


