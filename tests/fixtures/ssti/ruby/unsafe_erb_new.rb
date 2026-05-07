# Unsafe: ERB.new receives a tainted template *source* string from
# request params; SSTI fires on the source argument.

require "erb"

def handler(params)
  src = params[:template]
  template = ERB.new(src)
  template.result(binding)
end
