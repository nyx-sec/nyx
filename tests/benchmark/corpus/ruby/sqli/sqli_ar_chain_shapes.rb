class SearchController < ApplicationController
  def over_threshold
    q = params[:q]
    scope = Status.all
    scope.where("name = '#{q}'").count >= 3
  end

  def nested
    q = params[:q]
    rows = Status.joins(:account).merge(Account.where("n = '#{q}'")).to_a
    render json: rows
  end

  def later_call
    q = params[:q]
    row = Status.where(id: 1).order("#{q} desc").first
    render json: row
  end

  def modifier
    q = params[:q]
    ids = params[:ids]
    Status.where("x = '#{q}'").delete_all if ids.any?
  end

  def where_not
    q = params[:q]
    rows = Status.where.not(id: 1).where("n = '#{q}'").to_a
    render json: rows
  end
end
