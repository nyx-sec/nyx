# Safe: ERB.new receives a constant template source.  Local variables
# bound through `binding` may carry user input but do not activate SSTI.

require "erb"

def handler(params)
  name = params[:name]
  template = ERB.new("Hello, <%= name %>")
  template.result(binding)
end
