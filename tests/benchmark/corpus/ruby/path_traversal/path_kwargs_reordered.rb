def read_report(name, dir: '.', mode: 'r')
  File.read(File.join(dir, name))
end

def handler
  read_report('latest', mode: 'w', dir: ENV['REPORT_DIR'])
end
