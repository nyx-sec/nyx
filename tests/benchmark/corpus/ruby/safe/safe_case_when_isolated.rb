class ReportsController < ApplicationController
  def show
    path = "reports/summary.txt"
    case params[:mode]
    when "custom"
      path = params[:path]
      logger.info("custom reports are disabled")
    else
      render plain: File.read(path)
    end
  end
end
