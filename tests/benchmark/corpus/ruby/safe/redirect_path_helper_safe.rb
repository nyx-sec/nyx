class ThingsController < ApplicationController
  def update
    if @thing.save
      redirect_to things_path(:page => params[:page])
    end
  end

  def settings
    redirect_to settings_path(:tab => params[:tab])
  end

  def show
    target = thing_path(params[:id])
    redirect_to target
  end
end
