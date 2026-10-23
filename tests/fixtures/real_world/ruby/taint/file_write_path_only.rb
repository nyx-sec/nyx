class FeedbackController < ApplicationController
  def create
    File.write('/var/log/feedback.log', params[:text], mode: 'a')
    head :ok
  end

  def save
    File.binwrite("/var/data/#{params[:name]}", 'data')
    head :ok
  end
end
