export default {
  async fetch(request) {
    const url = new URL(request.url);
    const target = url.searchParams.get("url");

    if (!target) {
      return new Response("Missing ?url parameter", { status: 400 });
    }

    try {
      // Fetch the target URL
      const res = await fetch(target, {
        headers: {
          // Optional: forward headers from the original request
          'User-Agent': request.headers.get('User-Agent') || 'Cloudflare-Worker-Proxy',
        },
      });

      // Clone headers but remove restricted ones
      const newHeaders = new Headers(res.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*"); // Allow browser download
      newHeaders.delete("content-security-policy");
      newHeaders.delete("content-encoding"); // Prevent double compression

      // Return proxied response
      return new Response(res.body, {
        status: res.status,
        headers: newHeaders,
      });
    } catch (err) {
      return new Response("Error fetching target: " + err.message, { status: 500 });
    }
  },
};