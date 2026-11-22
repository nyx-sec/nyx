class JobsController < ApplicationController
  def run
    name = params[:name]
    job = Job.new
    job.execute(name)
    Worker.execute(name)
    head :ok
  end
end
