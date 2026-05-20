# Phase 21 (Track M.3) — Rails ActiveRecord migration vuln fixture.
#
# `AddIndex#up` invokes `execute(...)` with a raw, attacker-controlled
# table name concatenated into DDL — classic Rails migration SQLi.

# class AddIndex < ActiveRecord::Migration[7.0]

class AddIndex
  attr_accessor :table_name

  def up
    name = @table_name || ENV['NYX_PAYLOAD'].to_s
    # SINK: tainted table name spliced into raw DDL.
    execute("CREATE INDEX idx_#{name} ON users(name)")
  end

  def execute(sql)
    # The harness only asserts that execute() is invoked with the
    # tainted SQL string.  A real ActiveRecord::Base.connection would
    # forward to the DB driver.
    puts "MIGRATION_SQL: #{sql}"
  end
end
