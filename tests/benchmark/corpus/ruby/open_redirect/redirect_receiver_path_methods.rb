class LinksController < ApplicationController
  def unescape
    redirect_to Rack::Utils.unescape_path(params[:u])
  end

  def relative
    redirect_to Pathname.new(params[:u]).relative_path
  end

  def referer
    redirect_to request.referer_path || params[:u]
  end
end
