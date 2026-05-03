export function GET() {
  return new Response(
    `User-agent: *
Allow: /

Sitemap: https://dns.js.gripe/sitemap.xml
`,
    {
      headers: {
        "content-type": "text/plain; charset=utf-8"
      }
    }
  );
}
