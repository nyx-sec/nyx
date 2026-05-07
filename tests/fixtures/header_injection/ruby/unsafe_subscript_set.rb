# Unsafe: tainted request value flows into the bare-subscript header set
# `response.headers["X-Forwarded-By"] = lang`.  The LHS-subscript
# classification path matches `response.headers` as a HEADER_INJECTION
# sink so this form fires alongside the explicit `set_header` /
# `add_header` method-call shapes.
def handle(params, response)
  lang = params["lang"]
  response.headers["X-Forwarded-By"] = lang
end
