class RunController < ApplicationController
  def run
    cmd = params[:cmd]
    # Every payload is already a String.
    if cmd.is_a?(String)
      system(cmd)
    end
  end
end
