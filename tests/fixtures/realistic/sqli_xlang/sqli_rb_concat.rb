# Phase 15 — Ruby ActiveRecord `find_by_sql` raw-string concat SQLi
# positive.  `find_by_sql` is a flat SQL_QUERY sink in
# `labels/ruby.rs`; `params[:name]` flows directly into the SQL string
# via concatenation with no parameterisation.
class UsersController < ApplicationController
  def lookup
    name = params[:name]
    User.find_by_sql("SELECT * FROM users WHERE name = '" + name + "'")
  end
end
