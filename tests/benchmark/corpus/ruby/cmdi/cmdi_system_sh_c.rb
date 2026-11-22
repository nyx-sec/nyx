def run_script(params)
  cmd = params[:cmd]
  system("sh", "-c", cmd)
end
