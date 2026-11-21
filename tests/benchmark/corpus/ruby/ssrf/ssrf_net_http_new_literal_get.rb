require 'net/http'

class ProxyController < ApplicationController
  def status
    http = Net::HTTP.new(params[:host], 80)
    res = http.get("/status")
    render plain: res.body
  end
end
