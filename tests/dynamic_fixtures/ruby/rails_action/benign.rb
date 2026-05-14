# Phase 15 — Rails-style controller action, benign.

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
    payload = @__nyx_payload || ENV['NYX_PAYLOAD'] || ''
    unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
      STDOUT.print("invalid\n")
      return "invalid"
    end
    out = `echo hello`
    STDOUT.print(out)
    out
  end
end
