const pages = ["", "help/", "en/", "en/help/"];

export function GET() {
  const urls = pages
    .map(
      (page) => `<url><loc>https://dns.js.gripe/${page}</loc><changefreq>weekly</changefreq><priority>${page === "" ? "1.0" : "0.8"}</priority></url>`
    )
    .join("");

  return new Response(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`, {
    headers: {
      "content-type": "application/xml; charset=utf-8"
    }
  });
}
