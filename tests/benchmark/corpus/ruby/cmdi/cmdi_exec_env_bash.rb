def replace_process
  script = ENV['SCRIPT']
  exec("env", "bash", "-c", script)
end
