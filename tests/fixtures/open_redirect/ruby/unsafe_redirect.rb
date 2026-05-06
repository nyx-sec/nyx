# Unsafe: Rails `redirect_to(url)` receives a request-supplied URL.
class HomeController
  def jump
    target = params[:next]
    redirect_to target
  end
end
