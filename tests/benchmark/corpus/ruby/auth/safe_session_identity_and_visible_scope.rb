class OrdersController < ApplicationController
  before_action :require_login

  # The session identity key is the signed-in caller, not a request id.
  def show
    @user = User.find(session[:user_id])
    render json: @user
  end

  def index
    current_user_id = session[:uid]
    @orders = Order.where(user_id: current_user_id)
    render json: @orders
  end

  # `viewable_by` confines the lookup to rows the caller may see.
  def issue
    @issue = Issue.viewable_by(current_user).find(params[:id])
    render json: @issue
  end

  def nested
    @project = Project.viewable_by(current_user).where(id: params[:project_id]).first
    @item = @project.issues.viewable_by(current_user).find_by(id: params[:id])
    render json: @item
  end

  # `visible(current_user)` names the caller, so the local stays confined.
  def via_local
    scope = Project.visible(current_user)
    @project = scope.find(params[:id])
    render json: @project
  end
end
