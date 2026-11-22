// Astro endpoint: the `href` query parameter picks the fetched URL.
import type { APIRoute } from 'astro'

export const GET: APIRoute = (ctx) => {
  const href = ctx.url.searchParams.get('href')
  if (!href) {
    return new Response('Missing href', { status: 400 })
  }
  return fetch(new URL(href, ctx.url.origin))
}
