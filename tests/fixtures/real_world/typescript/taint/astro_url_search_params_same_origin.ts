// Same endpoint, but the target must stay on the site's own origin.
import type { APIRoute } from 'astro'

export const GET: APIRoute = (ctx) => {
  const href = ctx.url.searchParams.get('href')
  if (!href) {
    return new Response('Missing href', { status: 400 })
  }
  const target = new URL(href, ctx.url.origin)
  if (target.origin !== ctx.url.origin) {
    return new Response('Forbidden', { status: 403 })
  }
  return fetch(target)
}
