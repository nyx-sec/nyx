# Safe: query arg routed through `ensure_relative_url` which enforces a
# leading `/` and rejects scheme-prefixed values (relative-only path).
class HomeController
  def ensure_relative_url(raw)
    return '/' unless raw.is_a?(String)
    return '/' unless raw.start_with?('/')
    return '/' if raw.start_with?('//')
    raw
  end

  def jump
    target = params[:next]
    safe = ensure_relative_url(target)
    redirect_to safe
  end
end
