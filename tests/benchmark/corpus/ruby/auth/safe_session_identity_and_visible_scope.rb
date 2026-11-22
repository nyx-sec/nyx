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

  # `visible` confines the lookup to rows the caller may see.
  def issue
    @issue = Issue.visible.find(params[:id])
    render json: @issue
  end

  def nested
    @project = Project.visible.where(id: params[:project_id]).first
    @item = @project.issues.visible.find_by(id: params[:id])
    render json: @item
  end

  def via_local
    scope = Project.visible
    @project = scope.find(params[:id])
    render json: @project
  end
end
