class ReportsController < ApplicationController
  def bulk_set
    User.where(id: 1).update_all(seen: true)
  end

  def sort
    User.where(id: 1).reorder(:created_at)
  end

  def pick
    User.where(id: 1).select(:id, :name)
  end

  def count_active
    User.where(active: true).count
  end
end
