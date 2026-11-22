class AddReportIndexes < ActiveRecord::Migration[7.0]
  def up
    ActiveRecord::Base.connection.execute("UPDATE reports SET views = 0")
    Report.connection.execute("CREATE INDEX idx_reports_title ON reports (title)")
  end
end
