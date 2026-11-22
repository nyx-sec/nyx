class NotesController < ApplicationController
  before_action :require_login

  def show
    @note = Note.visible.find(params[:id])
    render json: @note
  end

  def show_local
    scope = Note.visible
    @note = scope.find(params[:id])
    render json: @note
  end

  def show_conditional
    uid = params[:id]
    uid = session[:user_id] if params[:me]
    @note = Note.find_by(user_id: uid)
    render json: @note
  end
end
