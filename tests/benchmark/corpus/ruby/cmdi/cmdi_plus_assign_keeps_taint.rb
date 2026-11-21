# Appending a literal flag with `+=` keeps the param in `cmd`.
def run_command(params)
  cmd = params[:cmd]
  cmd += ' --verbose'
  system(cmd)
end
