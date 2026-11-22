class LoadAndAuthorizeNotesController < ApplicationController
  load_and_authorize_resource

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
