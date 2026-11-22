class NotesController < ApplicationController
  before_action :require_login

  def show_local
    scope = Note.visible(current_user)
    @note = scope.find(params[:id])
    render json: @note
  end

  def show_session
    uid = session[:user_id]
    @note = Note.find_by(user_id: uid)
    render json: @note
  end
end
