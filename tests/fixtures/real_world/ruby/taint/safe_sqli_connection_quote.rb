class ReportsController < ApplicationController
  def search
    term = params[:term]
    quoted = ActiveRecord::Base.connection.quote(term)
    rows = ActiveRecord::Base.connection.execute("SELECT * FROM reports WHERE title = #{quoted}")
    render json: rows.to_a
  end
end
