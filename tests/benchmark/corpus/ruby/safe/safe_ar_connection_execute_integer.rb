class ReportsController < ApplicationController
  def show
    id = params[:id].to_i
    rows = ActiveRecord::Base.connection.execute("SELECT * FROM reports WHERE id = #{id}")
    render json: rows.to_a
  end
end
