class SessionsController < ApplicationController
  def after_login
    sign_in(user)
    redirect_to next_location
  end

  private

  def next_location
    target = request.referrer
    target
  end
end
