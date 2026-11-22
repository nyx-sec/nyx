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

  # `visible` without the caller is usually a publish flag, not authorization.
  def bare_visible
    @note = Note.visible.find(params[:id])
    render json: @note
  end

  def bare_visible_local
    scope = Note.visible
    @note = scope.find(params[:id])
    render json: @note
  end

  # The request id reaches the lookup through the branch that skips the session.
  def conditional_identity
    uid = params[:id]
    uid = session[:user_id] if params[:me]
    @note = Note.find_by(user_id: uid)
    render json: @note
  end
end
