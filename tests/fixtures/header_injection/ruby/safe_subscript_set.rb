# Safe: tainted request value routed through `strip_crlf` (a registered
# HEADER_INJECTION sanitizer) before the subscript-set, so taint-header-injection
# stays clean.
def handle(params, response)
  lang = params["lang"]
  response.headers["X-Forwarded-By"] = strip_crlf(lang)
end
