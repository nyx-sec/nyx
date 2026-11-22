class SessionsController < ApplicationController
  def after_timeout
    return_target = "/dashboard"
    redirect_to return_target
  end

  def after_login(return_target)
    redirect_to return_target
  end

  def after_logout
    %w[/a /b].each do |return_target|
      redirect_to return_target
    end
  end

  private

  def return_target
    request.referrer
  end
end
