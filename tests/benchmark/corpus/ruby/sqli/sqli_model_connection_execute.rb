class ReportsController < ApplicationController
  def purge
    table = params[:table]
    Report.connection.execute("DELETE FROM #{table} WHERE stale = 1")
    head :ok
  end
end
