class Dispatcher
  def call(obj, params)
    %w[a b].each { |n| [params[:m]].each { |n| obj.send(n) } }
  end
end
