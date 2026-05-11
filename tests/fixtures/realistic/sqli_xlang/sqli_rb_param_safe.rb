# Phase 15 negative — Ruby ActiveRecord `where` placeholder-bind safe.
# `where("name = ?", x)` is the parameterised form recognised by
# `cfg::ar_query_safe_shape` (Ruby labels module); the synthesised
# `Sanitizer(SQL_QUERY)` clears the cap on the call, suppressing the
# `where` SQL_QUERY sink even though the bind value is tainted.
class UsersController < ApplicationController
  def lookup
    name = params[:name]
    User.where("name = ?", name)
  end
end
