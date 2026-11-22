# `only: %i[..]` limits the filter to the listed actions; `archive` is not
# one of them.
class ArchivedNotesController < ApplicationController
  before_action :authorize_owner!, only: %i[update destroy]

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def archive
    note = Note.find(params[:id])
    note.update(archived: true)
  end
end
