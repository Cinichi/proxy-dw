// api/drive/[...proxy]/route.ts
// Google Drive Proxy v3.5.1 - Vercel Edge Runtime
// Deploy as: vercel --prod with GOOGLE_SERVICE_ACCOUNT* env vars

import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'edge';

export async function GET(
  request: NextRequest,
  { params }: { params: { ' [...proxy]': string[] } }
) {
  try {
    return await handleRequest(request);
  } catch (error: any) {
    console.error('Worker error:', error);
    return jsonResponse({ error: 'Server error', details: error.message }, 500);
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { 
    status: 200, 
    headers: getCorsHeaders() 
  });
}

async function handleRequest(request: NextRequest) {
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
        driveIdApi: '?id=FILE_ID&api=true (recommended)',
        driveUrl: '?url=https://drive.google.com/file/d/ID/view'
      }
    }, 400);
  }

  // API path (fastest with service accounts)
  if (extractedFileId && !forceDirect && (forceApi || hasServiceAccounts())) {
    try {
      return await handleDriveApiRequest(request, extractedFileId);
    } catch (apiError: any) {
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

  return await fetchDirect(request, targetUrl, validation.url, url.searchParams);
}

function hasServiceAccounts(): boolean {
  return !!(
    process.env.GOOGLE_SERVICE_ACCOUNT || 
    process.env.GOOGLE_SERVICE_ACCOUNT_1 || 
    process.env.GOOGLE_SERVICE_ACCOUNT_2
  );
}

function getAllServiceAccounts() {
  const accounts: any[] = [];
  for (let i = 0; i <= 10; i++) {
    const key = i === 0 ? 'GOOGLE_SERVICE_ACCOUNT' : `GOOGLE_SERVICE_ACCOUNT_${i}`;
    const json = process.env[key as keyof typeof process.env];
    if (json) {
      try {
        accounts.push(JSON.parse(json));
      } catch (e) {
        console.error(`Invalid JSON in ${key}`);
      }
    }
  }
  return accounts;
}

async function handleDriveApiRequest(request: NextRequest, fileId: string) {
  const serviceAccounts = getAllServiceAccounts();
  if (serviceAccounts.length === 0) throw new Error('No service accounts');

  let lastError: any = null;
  for (let i = 0; i < serviceAccounts.length; i++) {
    try {
      const result = await tryServiceAccount(request, fileId, serviceAccounts[i], i);
      if (result) return result;
    } catch (error: any) {
      console.warn(`Account ${i} failed:`, error.message);
      lastError = error;
      if (error.message.includes('404') || error.message.includes('not found')) throw error;
    }
  }
  throw lastError || new Error('All accounts failed');
}

async function getFileMetadata(fileId: string, accessToken: string) {
  const cacheKey = `meta:${fileId}`;
  // Vercel Edge: Use Cache-Control headers instead of caches.default
  const cacheUrl = `https://cache.internal/${cacheKey}`;
  
  const cached = await fetch(cacheUrl, { cache: 'force-cache' });
  if (cached.ok) {
    return await cached.json();
  }
  
  const metaUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?fields=size,name,mimeType,md5Checksum,modifiedTime`;
  const metaResp = await fetch(metaUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` },
    cache: 'no-store' // Fresh metadata
  });
  
  if (!metaResp.ok) {
    if (metaResp.status === 404) throw new Error('File not found');
    if (metaResp.status === 403) throw new Error('File not accessible');
    throw new Error(`Metadata failed: ${metaResp.status}`);
  }
  
  const metadata = await metaResp.json();
  
  // Cache metadata response for 10min
  const cacheResp = NextResponse.json(metadata, {
    headers: { 'Cache-Control': 'public, max-age=600, s-maxage=600' }
  });
  
  return metadata;
}

async function tryServiceAccount(
  request: NextRequest, 
  fileId: string, 
  serviceAccount: any, 
  accountIndex: number
) {
  const accessToken = await getGoogleAccessToken(serviceAccount);
  if (!accessToken) throw new Error('No access token');

  const metadata = await getFileMetadata(fileId, accessToken);
  
  const fileName = metadata.name || 'download';
  const fileSize = parseInt(metadata.size || '0', 10);
  const mimeType = metadata.mimeType || 'application/octet-stream';
  const isGoogleDoc = mimeType.startsWith('application/vnd.google-apps.');
  
  const rangeHeader = request.headers.get('Range');

  // HEAD request
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
      headers: headHeaders,
      cache: 'no-store'
    });
    
    const headers = new Headers();
    let responseStatus = 200;
    
    if (headResp.status === 206 && headResp.headers.has('Content-Range')) {
      const range = headResp.headers.get('Content-Range');
      const match = range.match(/bytes d+-d+/(d+)/);
      if (match) {
        headers.set('Content-Length', match[1]);
      }
      headers.set('Content-Range', headResp.headers.get('Content-Range'));
      responseStatus = 206;
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
    return new NextResponse(null, { status: responseStatus, headers });
  }

  // GET request
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
    cf: { cacheTtl: 3600 } // Vercel equivalent
  });

  if (!response.ok) {
    throw new Error(`Download failed: ${response.status}`);
  }

  const finalHeaders = new Headers();
  
  if (response.status === 206) {
    ['Content-Type', 'Content-Range', 'Content-Length', 'ETag', 'Last-Modified'].forEach(h => {
      if (response.headers.has(h)) {
        finalHeaders.set(h, response.headers.get(h));
      }
    });
    finalHeaders.set('Accept-Ranges', 'bytes');
  } else {
    finalHeaders.set('Content-Type', response.headers.get('Content-Type') || mimeType);
    finalHeaders.set('Accept-Ranges', isGoogleDoc ? 'none' : 'bytes');
    
    if (response.headers.has('Content-Length')) {
      finalHeaders.set('Content-Length', response.headers.get('Content-Length'));
    } else if (!isGoogleDoc && fileSize > 0) {
      finalHeaders.set('Content-Length', String(fileSize));
    }
  }
  
  finalHeaders.set('Content-Disposition', buildContentDisposition(fileName));
  finalHeaders.set('X-Drive-API', 'true');
  finalHeaders.set('X-Account', String(accountIndex));
  finalHeaders.set('Cache-Control', 'public, max-age=3600');
  
  if (metadata.md5Checksum && !isGoogleDoc) {
    finalHeaders.set('ETag', `"${metadata.md5Checksum}"`);
  }
  if (metadata.modifiedTime) {
    finalHeaders.set('Last-Modified', new Date(metadata.modifiedTime).toUTCString());
  }
  
  addCorsHeaders(finalHeaders);
  
  return new NextResponse(response.body, { 
    status: response.status, 
    headers: finalHeaders 
  });
}

async function getGoogleAccessToken(serviceAccount: any): Promise<string | null> {
  const email = serviceAccount.client_email;
  const cacheKey = `auth:${btoa(email)}`;
  
  // Vercel: Simple cache via fetch with force-cache
  const cached = await fetch(`https://auth.internal/${cacheKey}`, { 
    cache: 'force-cache' 
  });
  if (cached.ok) {
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
    
    // Cache for 50 minutes via headers
    const cacheResp = new Response(token, {
      headers: { 'Cache-Control': 'public, max-age=3000, s-maxage=3000' }
    });
    
    return token;
  } catch (error) {
    console.error('Token error:', error);
    return null;
  }
}

async function importPrivateKey(pemKey: string) {
  const pemContents = pemKey
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/s/g, '');
  const binaryKey = base64Decode(pemContents);
  return await crypto.subtle.importKey(
    'pkcs8',
    binaryKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

function base64UrlEncode(data: any) {
  const bytes = typeof data === 'string' 
    ? new TextEncoder().encode(data)
    : new Uint8Array(data);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/+/g, '-').replace(///g, '_').replace(/=/g, '');
}

function base64Decode(str: string) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Rest of helpers unchanged
function buildExportUrl(fileId: string, mimeType: string) {
  const exportMap: Record<string, string> = {
    'application/vnd.google-apps.document': 'application/pdf',
    'application/vnd.google-apps.spreadsheet': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.google-apps.presentation': 'application/pdf'
  };
  const exportMimeType = exportMap[mimeType] || 'application/pdf';
  return `https://www.googleapis.com/drive/v3/files/${fileId}/export?mimeType=${encodeURIComponent(exportMimeType)}`;
}

function buildContentDisposition(fileName: string) {
  const safeAscii = fileName.replace(/[^w.- ]+/g, '_').slice(0, 200);
  return `attachment; filename="${safeAscii}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
}

function buildGoogleDriveUrl(fileId: string) {
  const uuid = deterministicUUID(fileId);
  return `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=t&uuid=${uuid}`;
}

function deterministicUUID(fileId: string) {
  const encoded = btoa(fileId).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8);
  return `${encoded.slice(0, 4)}-${encoded.slice(4, 8)}`;
}

function extractGoogleDriveId(url: string) {
  const match = url.match(//file/d/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];
  try {
    return new URL(url).searchParams.get('id');
  } catch {
    return null;
  }
}

async function fetchDirect(
  request: NextRequest, 
  targetUrl: string, 
  parsedTarget: URL, 
  params: URLSearchParams
) {
  const proxyHeaders = buildHeaders(request, parsedTarget, params);
  const rangeHeader = request.headers.get('Range');
  
  if (request.method === 'HEAD') {
    proxyHeaders.set('Range', 'bytes=0-0');
    const resp = await fetch(targetUrl, { 
      method: 'GET',
      headers: proxyHeaders,
      redirect: 'follow'
    });
    
    const headers = new Headers();
    let responseStatus = 200;
    
    if (resp.status === 206 && resp.headers.has('Content-Range')) {
      const range = resp.headers.get('Content-Range');
      const match = range.match(/bytes d+-d+/(d+)/);
      if (match) {
        headers.set('Content-Length', match[1]);
      }
      headers.set('Content-Range', resp.headers.get('Content-Range'));
      responseStatus = 206;
    } else if (resp.headers.has('Content-Length')) {
      headers.set('Content-Length', resp.headers.get('Content-Length'));
    }
    
    ['Content-Type', 'ETag', 'Last-Modified'].forEach(h => {
      if (resp.headers.has(h)) headers.set(h, resp.headers.get(h));
    });
    
    headers.set('Accept-Ranges', 'bytes');
    addCorsHeaders(headers);
    return new NextResponse(null, { status: responseStatus, headers });
  }

  const response = await fetch(targetUrl, {
    method: 'GET',
    headers: proxyHeaders,
    redirect: 'follow'
  });

  if (response.ok && response.headers.get('content-type')?.includes('text/html')) {
    const text = await response.text();
    if (text.includes("Sorry, you can't view or download")) {
      return jsonResponse({
        error: 'Quota exceeded',
        tip: 'Use ?api=true with service accounts'
      }, 429);
    }
  }

  if (!response.ok) {
    if (response.status === 404) return jsonResponse({ error: 'Not found' }, 404);
    if (response.status >= 500) return jsonResponse({ error: 'Origin error' }, 502);
  }

  const finalHeaders = buildResponseHeaders(response);
  const filename = extractFilename(response, targetUrl);
  if (filename && !finalHeaders.has('Content-Disposition')) {
    finalHeaders.set('Content-Disposition', buildContentDisposition(filename));
  }

  return new NextResponse(response.body, { 
    status: response.status, 
    headers: finalHeaders 
  });
}

function extractFilename(response: Response, url: string) {
  const cd = response.headers.get('Content-Disposition');
  if (cd) {
    const match = cd.match(/filename[^;=
]*=((['"]).*?\u0002|[^;
]*)/);
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

function buildHeaders(request: NextRequest, target: URL, params: URLSearchParams) {
  const headers = new Headers();
  
  ['Range', 'If-Range', 'If-None-Match', 'If-Modified-Since'].forEach(h => {
    const value = request.headers.get(h);
    if (value) headers.set(h, value);
  });
  
  headers.set('User-Agent', request.headers.get('User-Agent') || 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36');
  headers.set('Accept', '*/*');
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

function buildResponseHeaders(response: Response) {
  const headers = new Headers(response.headers);
  addCorsHeaders(headers);
  
  if (!headers.has('Accept-Ranges')) headers.set('Accept-Ranges', 'bytes');
  headers.delete('Content-Encoding');
  headers.set('Cache-Control', 'public, max-age=3600');
  
  ['Content-Security-Policy', 'X-Frame-Options', 'Set-Cookie'].forEach(h => headers.delete(h));
  return headers;
}

function validateTargetUrl(url: string) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, error: 'Invalid protocol', status: 400 };
    }
    
    const hostname = parsed.hostname.toLowerCase();
    const privatePatterns = [
      'localhost', '127.0.0.1', '::1', '0.0.0.0',
      /^192.168./, /^10./, /^172.(1[6-9]|2[0-9]|3[0-1])./
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

function addCorsHeaders(headers: Headers) {
  Object.entries(getCorsHeaders()).forEach(([k, v]) => headers.set(k, v as string));
}

function jsonResponse(data: any, status: number) {
  return NextResponse.json(data, {
    status,
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}
