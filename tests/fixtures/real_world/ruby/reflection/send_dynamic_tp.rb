class Dispatcher
  def call(obj, name)
    obj.send(name)
  end

  def call_interpolated(obj, kind)
    obj.send("handle_#{kind}")
  end
end
