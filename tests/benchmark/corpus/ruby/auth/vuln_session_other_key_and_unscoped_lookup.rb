class OrdersController < ApplicationController
  before_action :require_login

  # Recall guards for safe_session_identity_and_visible_scope.rb.
  def cart
    @cart = Cart.find(session[:cart_id])
    render json: @cart
  end

  def workspace
    @ws = Workspace.find(session[:workspace_id])
    render json: @ws
  end

  def impersonated
    @user = User.find(session[:impersonated_user_id])
    render json: @user
  end

  def unscoped
    @issue = Issue.find(params[:id])
    render json: @issue
  end

  def rebound
    scope = Project.visible
    scope = Project.all
    @project = scope.find(params[:id])
    render json: @project
  end
end
