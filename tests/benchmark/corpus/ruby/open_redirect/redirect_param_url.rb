class GoController < ApplicationController
  def go
    redirect_to params[:url]
  end
end
