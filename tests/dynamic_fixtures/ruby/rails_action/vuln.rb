# Ruby ActionController action, vulnerable.
# The harness drives UsersController.action(:index) through Rack.

require 'action_controller'

class ApplicationController < ActionController::Base
  self.view_paths = []
end

class UsersController < ApplicationController
  def index
    STDOUT.print("__NYX_SINK_HIT__\n")
    payload = params[:payload].to_s
    out = `echo hello #{payload}`
    STDOUT.print(out)
    render plain: out
  end
end
