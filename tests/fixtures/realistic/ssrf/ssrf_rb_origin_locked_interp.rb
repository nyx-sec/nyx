# Phase 14 fixture (Ruby negative) — string interpolation with a
# literal origin prefix anchors a `string_prefix` for the SSA
# transfer, which seeds a `StringFact` with locked host on the URL
# SSA value.  `is_string_safe_for_ssrf` suppresses the SSRF sink at
# `Net::HTTP.get` even though `params[:id]` is attacker-controlled.
#
# Tree-sitter-ruby parses `"https://api.example.com/users/#{id}"`
# as a `string` node containing `string_content` and `interpolation`
# children.  `prefix_of_expression` Case 4 recognises the leading
# `string_content` as the locked prefix.
require 'net/http'
require 'uri'

class UserLookup
  def show(params)
    id = params[:id]
    url = "https://api.example.com/users/#{id}"
    Net::HTTP.get(URI(url))
  end
end
