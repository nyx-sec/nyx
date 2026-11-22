class SkipOnlyNotesController < ApplicationController
  before_action :authorize_owner!
  skip_before_action :authorize_owner!, only: %i[preview]

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def preview
    @note = Note.find(params[:id])
  end
end
