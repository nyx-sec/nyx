# post_default_aspects takes no parameters and reads no request data.  The
# unrelated helper below has a parameter; that must not make the query
# above look like it receives caller data.
class User < ApplicationRecord
  def post_default_aspects
    x = aspects.where(Principal.fields_for_order_statement)
    x
  end

  def unrelated(y)
    y + 1
  end
end
