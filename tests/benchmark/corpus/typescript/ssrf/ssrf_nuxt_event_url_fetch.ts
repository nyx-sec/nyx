// Nitro handler: the request URL reaches `$fetch` with no host check.
import { defineEventHandler } from 'h3'

export default defineEventHandler(async (event) => {
  const url = event.node.req.url
  const apiUrl = new URL(url, 'https://api.example.com')
  return await $fetch(apiUrl.href)
})
