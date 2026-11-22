def read_report(name, dir = '.')
  File.read(File.join(dir, name))
end

def handler
  read_report('latest', ENV['REPORT_DIR'])
end
