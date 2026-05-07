# Safe: query arg routed through `validate_redirect_url` allowlist before
# being passed to redirect_to.
class HomeController
  def validate_redirect_url(raw)
    raw.is_a?(String) && raw.start_with?('/') ? raw : '/'
  end

  def jump
    target = params[:next]
    safe = validate_redirect_url(target)
    redirect_to safe
  end
end
