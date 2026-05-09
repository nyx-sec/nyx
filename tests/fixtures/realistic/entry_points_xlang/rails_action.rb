# Phase 16 fixture: Rails ActionController action.  `UsersController`
# extends `ApplicationController`; `show` is recognised as a
# `RailsAction` entry point.  Rails actions take no formal parameters,
# adversary input flows in through the implicit `params` accessor
# (already a Source in `labels/ruby.rs`).  The fixture demonstrates
# entry-point recognition composing with the existing `params` source
# and the flat `find_by_sql` SQL_QUERY sink shipped in Phase 15.
class UsersController < ApplicationController
  def show
    name = params[:name]
    User.find_by_sql("SELECT * FROM users WHERE name = '" + name + "'")
  end
end
