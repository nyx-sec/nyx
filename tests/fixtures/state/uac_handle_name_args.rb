require 'tempfile'

# Tempfile#path stays valid after close (until unlink / close!).
def convert(data)
  tmp = Tempfile.new('x')
  tmp.write(data)
  tmp.close
  out = File.read(tmp.path)
  out
end

def path_after_close(data)
  tmp = Tempfile.new('x')
  tmp.write(data)
  tmp.close
  p = tmp.path
  p
end

def show(p, io)
  f = File.open(p)
  f.close
  io.write(f.path)
end
