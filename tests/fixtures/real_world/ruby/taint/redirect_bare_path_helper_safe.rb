class LinksController < ApplicationController
  def index
    redirect_to links_path(:q => params[:q])
  end

  def show
    redirect_to link_path(params[:id], :tab => params[:tab])
  end
end
