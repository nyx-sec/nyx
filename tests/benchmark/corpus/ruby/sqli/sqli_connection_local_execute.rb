class ReportsController < ApplicationController
  def search
    term = params[:term]
    conn = ActiveRecord::Base.connection
    rows = conn.execute("SELECT * FROM reports WHERE title = '#{term}'")
    render json: rows.to_a
  end
end
