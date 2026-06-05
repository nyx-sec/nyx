require "hanami/action"

module Books
  class Show
    include Hanami::Action

    def call(req)
      req.params[:id]
    end
  end
end
