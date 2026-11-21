class UsersController < ApplicationController
  def search
    q = params[:q]
    @users = User.where("name LIKE '%#{q}%' AND active = ?", true)
    render json: @users
  end

  def by_table
    q = params[:q]
    @users = User.where("#{User.table_name}.name = ?", q)
    render json: @users
  end

  def plain
    q = params[:q]
    @users = User.where("name = ? AND active = ?", q, true)
    render json: @users
  end
end
