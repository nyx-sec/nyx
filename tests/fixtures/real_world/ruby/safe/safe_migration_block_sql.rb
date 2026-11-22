class AddUniqueIndex < ActiveRecord::Migration[4.2]
  def up
    table_name = "#{CustomField.table_name_prefix}custom_fields_trackers"
    duplicates = CustomField.connection.select_rows("SELECT a, b FROM #{table_name}")
    duplicates.each do |custom_field_id, tracker_id|
      CustomField.connection.execute("DELETE FROM #{table_name} WHERE a=#{custom_field_id} AND b=#{tracker_id}")
    end
  end
end
