# Unsafe: "/#{next}" with next = "/evil.example" is protocol-relative.
class SessionsController < ApplicationController
  def back
    redirect_to "/#{params[:next]}"
  end
end
