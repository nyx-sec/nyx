# The sink call is the `if` condition itself.
class JobsController < ApplicationController
  def run
    cmd = params[:cmd]
    if system(cmd)
      render plain: "ok"
    end
  end
end
