class RunController < ApplicationController
  def run
    cmd = params[:cmd]
    case params[:mode]
    when "quit"
      return
    else
      system(cmd)
    end
    render plain: "ok"
  end
end
