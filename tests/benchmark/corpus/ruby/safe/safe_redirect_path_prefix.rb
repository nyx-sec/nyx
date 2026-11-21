class UsersController < ApplicationController
  def go
    redirect_to "/users/#{params[:id]}"
  end
end
