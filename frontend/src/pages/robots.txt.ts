export function GET() {
  return new Response(
    `# Claude is not welcome here because this site owner does not welcome
# unethical AI crawlers that freely scrape sites while arbitrarily
# banning user accounts.
User-agent: ClaudeBot
Disallow: /

User-agent: Claude-User
Disallow: /

User-agent: *
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
