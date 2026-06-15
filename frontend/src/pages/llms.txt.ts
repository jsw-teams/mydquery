export function GET() {
  return new Response(
    `# dquery.js.gripe

dquery.js.gripe is a public DNS-over-HTTPS query console.

Primary pages:
- https://dquery.js.gripe/
- https://dquery.js.gripe/help/
- https://dquery.js.gripe/en/
- https://dquery.js.gripe/en/help/

Public DoH endpoint:
- https://dquery.js.gripe/dns-query
`,
    {
      headers: {
        "content-type": "text/plain; charset=utf-8"
      }
    }
  );
}
