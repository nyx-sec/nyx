class ReportsController < ApplicationController
  def search
    term = params[:term]
    sql = ActiveRecord::Base.sanitize_sql(["SELECT * FROM reports WHERE title LIKE ?", "%#{term}%"])
    rows = ActiveRecord::Base.connection.execute(sql)
    render json: rows.to_a
  end
end
