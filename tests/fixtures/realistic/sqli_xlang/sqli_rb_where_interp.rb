# Phase 15 — Ruby ActiveRecord `where` string-interpolation SQLi
# positive.  `where` is a SQL_QUERY sink in `labels/ruby.rs`; the
# string-interpolation form (`"name = '#{name}'"`) is the canonical
# Rails SQLi vector when the cfg `ar_query_safe_shape` recognises a
# non-parameterised string argument.
class UsersController < ApplicationController
  def lookup
    name = params[:name]
    User.where("name = '#{name}'")
  end
end
