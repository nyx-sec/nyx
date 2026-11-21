class ExceptListNotesController < ApplicationController
  before_action :authorize_owner!, except: %i[index]

  def index
    @notes = Note.where(public: true)
  end

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def destroy
    note = Note.find(params[:id])
    note.destroy
  end
end
