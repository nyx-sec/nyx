# The method returns inside begin; the ensure clause still runs.
class JobsController < ApplicationController
  def cleanup
    dir = params[:dir]
    begin
      return render(plain: "ok")
    ensure
      system("rm -rf " + dir)
    end
  end
end
