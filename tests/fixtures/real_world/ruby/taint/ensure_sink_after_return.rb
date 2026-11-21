class JobsController < ApplicationController
  # The begin body returns, and the ensure clause still runs.
  def cleanup
    dir = params[:dir]
    begin
      return render(plain: "ok")
    ensure
      system("rm -rf " + dir)
    end
  end

  # Method-level ensure.
  def purge
    dir = params[:dir]
    return render(plain: "ok")
  ensure
    system("rm -rf " + dir)
  end

  def rotate
    params[:dir]
    return render(plain: "ok")
  ensure
    system("logrotate /etc/app.conf")
  end
end
