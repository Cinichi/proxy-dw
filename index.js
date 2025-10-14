// Proxy with Range/Chunk Download Support
// Supports video streaming, resume downloads, and parallel chunks

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
          'Access-Control-Allow-Headers': 'Range, Content-Type',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    // Only allow GET and HEAD
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method not allowed', { status: 405 });
    }

    const url = new URL(request.url);
    const targetUrl = url.searchParams.get('url');

    // Validate target URL
    if (!targetUrl) {
      return new Response('Missing ?url= parameter', { status: 400 });
    }

    // Validate URL format
    let parsedTarget;
    try {
      parsedTarget = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsedTarget.protocol)) {
        throw new Error('Invalid protocol');
      }
    } catch (e) {
      return redirect(targetUrl);
    }

    // Check cache first
    const cache = caches.default;
    const cacheKey = new Request(targetUrl, { 
      method: 'GET',
      headers: request.headers 
    });
    
    // For range requests, don't use cache (to avoid issues)
    const rangeHeader = request.headers.get('Range');
    
    if (!rangeHeader) {
      // No range request - try cache
      let cachedResponse = await cache.match(cacheKey);
      
      if (cachedResponse) {
        const headers = new Headers(cachedResponse.headers);
        headers.set('X-Cache-Status', 'HIT');
        headers.set('Access-Control-Allow-Origin', '*');
        headers.set('Access-Control-Expose-Headers', 'Content-Range, Accept-Ranges, Content-Length');
        
        return new Response(cachedResponse.body, {
          status: cachedResponse.status,
          headers: headers
        });
      }
    }

    // Fetch from origin
    try {
      // Build request headers
      const proxyHeaders = new Headers();
      
      // Copy important headers from original request
      const headersToForward = [
        'Range',
        'If-Range',
        'If-Match',
        'If-None-Match',
        'If-Modified-Since',
        'If-Unmodified-Since',
        'Accept',
        'Accept-Encoding',
      ];
      
      headersToForward.forEach(header => {
        const value = request.headers.get(header);
        if (value) {
          proxyHeaders.set(header, value);
        }
      });

      // Add required headers
      proxyHeaders.set('User-Agent', 
        request.headers.get('User-Agent') || 
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      );
      proxyHeaders.set('Referer', parsedTarget.origin);
      
      // Fetch target
      const response = await fetch(targetUrl, {
        method: request.method,
        headers: proxyHeaders,
        cf: {
          cacheTtl: 86400,
          cacheEverything: true,
        }
      });

      // Handle errors
      if (!response.ok && response.status >= 400 && response.status !== 404 && response.status !== 416) {
        return redirect(targetUrl);
      }

      // Build response headers
      const responseHeaders = new Headers(response.headers);
      
      // CORS headers
      responseHeaders.set('Access-Control-Allow-Origin', '*');
      responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
      responseHeaders.set('Access-Control-Expose-Headers', 
        'Content-Range, Accept-Ranges, Content-Length, Content-Type, X-Cache-Status'
      );
      
      // Keep range-related headers
      if (response.headers.has('Accept-Ranges')) {
        responseHeaders.set('Accept-Ranges', response.headers.get('Accept-Ranges'));
      } else {
        responseHeaders.set('Accept-Ranges', 'bytes');
      }
      
      if (response.headers.has('Content-Range')) {
        responseHeaders.set('Content-Range', response.headers.get('Content-Range'));
      }
      
      // Cache control
      if (!rangeHeader) {
        responseHeaders.set('Cache-Control', 'public, max-age=86400, immutable');
        responseHeaders.set('X-Cache-Status', 'MISS');
      }
      
      // Remove problematic headers
      responseHeaders.delete('Content-Security-Policy');
      responseHeaders.delete('X-Frame-Options');
      responseHeaders.delete('X-Content-Type-Options');
      
      // For video/audio, ensure proper content-type
      const contentType = response.headers.get('Content-Type');
      if (contentType) {
        responseHeaders.set('Content-Type', contentType);
      }

      // Cache non-range requests
      if (!rangeHeader && response.ok) {
        const responseToCache = response.clone();
        ctx.waitUntil(cache.put(cacheKey, responseToCache));
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });

    } catch (error) {
      console.error('Proxy error:', error.message);
      return redirect(targetUrl);
    }
  }
};

// Helper function to redirect to original URL
function redirect(url) {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': url,
      'Cache-Control': 'no-cache'
    }
  });
    }
