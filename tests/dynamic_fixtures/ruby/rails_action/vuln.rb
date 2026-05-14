# Phase 15 — Rails-style controller action, vulnerable.
# Controller inherits the conventional ApplicationController name so
# RubyShape::detect picks RailsAction.

class ApplicationController
  def initialize; end
end

class UsersController < ApplicationController
  def initialize
    super
    @__nyx_payload = nil
    @__nyx_request = nil
  end

  def index
    STDOUT.print("__NYX_SINK_HIT__\n")
    payload = @__nyx_payload || ENV['NYX_PAYLOAD'] || ''
    out = `echo hello #{payload}`
    STDOUT.print(out)
    out
  end
end
