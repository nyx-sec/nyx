class ForeignUserNotesController < ApplicationController
  before_action :authenticate_user!

  def index
    render json: Note.where(user_id: params[:user_id])
  end

  def destroy
    Note.find(params[:id]).destroy
  end
end
