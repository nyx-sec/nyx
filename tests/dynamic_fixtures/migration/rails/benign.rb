# Phase 21 — Rails migration benign control.
# class AddIndex < ActiveRecord::Migration[7.0]

class AddIndex
  def up
    add_column :users, :name, :string
  end

  def add_column(table, name, type)
    puts "MIGRATION_ADD_COLUMN: #{table}.#{name} :: #{type}"
  end
end
