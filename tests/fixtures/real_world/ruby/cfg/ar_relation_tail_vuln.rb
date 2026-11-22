class ReportsController < ApplicationController
  def bulk_set
    User.where(id: 1).update_all("a = #{params[:o]}")
  end

  def sort
    User.where(id: 1).reorder(params[:o])
  end

  def pick
    User.where(id: 1).select(params[:o])
  end

  def raw_set
    User.where(active: true).update_all(params[:set])
  end
end
