class DocsController < ApplicationController
  def destroy
    doc = Document.find_by(id: params[:id])
    doc.destroy
  end

  def show
    @doc = Document.find_by!(id: params[:id])
  end
end
