// Same handler, but the parsed URL must keep the trusted API host.
import { defineEventHandler } from 'h3'

const API = 'https://api.example.com'

export default defineEventHandler(async (event) => {
  const url = event.node.req.url
  const apiUrl = new URL(url, API)
  if (apiUrl.host !== new URL(API).host) {
    return { error: 'invalid request' }
  }
  return await $fetch(apiUrl.href)
})
