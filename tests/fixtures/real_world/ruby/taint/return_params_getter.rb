class JobsController < ApplicationController
  def requested_id
    return params[:id]
  end

  def run
    id = requested_id()
    system("echo #{id}")
  end
end
