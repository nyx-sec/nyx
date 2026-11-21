# Safe: fixed same-origin path prefix on the redirect target.
class UsersController < ApplicationController
  def go
    redirect_to "/users/#{params[:id]}"
  end
end
