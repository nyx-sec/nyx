class CurrentUserNotesController < ApplicationController
  before_action :authenticate_user!

  def create
    note = Note.create(user_id: current_user.id, body: params[:body])
    render json: note
  end

  def index
    render json: Note.where(user_id: current_user.id)
  end

  def show
    @note = current_user.notes.find(params[:id])
  end

  def destroy
    current_user.notes.find(params[:id]).destroy
  end
end
