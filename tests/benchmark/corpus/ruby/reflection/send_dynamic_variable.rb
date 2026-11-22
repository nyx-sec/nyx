class Dispatcher
  def call(obj, params)
    name = params[:action]
    obj.send(name)
  end
end
