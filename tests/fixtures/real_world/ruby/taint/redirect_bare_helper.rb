class SessionsController < ApplicationController
  def after_timeout
    redirect_to return_target
  end

  private

  def return_target
    request.referrer
  end
end
