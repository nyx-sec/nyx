class UsersController < ApplicationController
  def search
    q = params[:q]
    @users = User.where("name LIKE '%#{q}%' AND active = ?", true)
    render json: @users
  end
end
