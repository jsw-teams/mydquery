export function GET() {
  return new Response(
    `# dns.js.gripe

dns.js.gripe is a public DNS-over-HTTPS query console.

Primary pages:
- https://dns.js.gripe/
- https://dns.js.gripe/help/
- https://dns.js.gripe/en/
- https://dns.js.gripe/en/help/

Public DoH endpoint:
- https://gateway.js.gripe/api/v1/dquery
`,
    {
      headers: {
        "content-type": "text/plain; charset=utf-8"
      }
    }
  );
}
