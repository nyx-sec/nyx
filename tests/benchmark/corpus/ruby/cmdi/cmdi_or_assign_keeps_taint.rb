# `||=` only assigns when `cmd` is nil, so the param survives.
def run_command(params)
  cmd = params[:cmd]
  cmd ||= 'ls'
  system(cmd)
end
