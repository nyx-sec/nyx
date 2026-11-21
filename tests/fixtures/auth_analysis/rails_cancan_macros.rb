class CancanNotesController < ApplicationController
  load_and_authorize_resource only: %i[destroy]

  def destroy
    note = Note.find(params[:id])
    note.destroy
  end

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
