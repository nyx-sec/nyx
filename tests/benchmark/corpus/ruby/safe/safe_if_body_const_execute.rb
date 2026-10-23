# The tainted mode only picks the branch; the SQL run in the body is a
# constant.  The `if` header must not take the body's sink.
class ReportsController < ApplicationController
  def index
    mode = params[:mode]
    if mode == "full"
      User.connection.execute("SELECT 1")
    end
    head :ok
  end
end
