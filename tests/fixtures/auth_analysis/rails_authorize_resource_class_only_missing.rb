class ClassOnlyNotesController < ApplicationController
  authorize_resource only: %i[destroy]

  def destroy
    note = Note.find(params[:id])
    note.destroy
  end
end
