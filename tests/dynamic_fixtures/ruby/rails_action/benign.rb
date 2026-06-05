# Ruby ActionController action, benign.

require 'action_controller'

class ApplicationController < ActionController::Base
  self.view_paths = []
end

class UsersController < ApplicationController
  def index
    payload = params[:payload].to_s
    unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
      STDOUT.print("invalid\n")
      render plain: "invalid"
      return
    end
    out = `echo hello`
    STDOUT.print(out)
    render plain: out
  end
end
