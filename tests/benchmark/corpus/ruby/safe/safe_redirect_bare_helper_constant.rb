class SessionsController < ApplicationController
  def after_timeout
    redirect_to fallback_location
  end

  private

  def fallback_location
    "/dashboard"
  end
end
