# A Ruby method returns its last expression, so each of these hands the
# file to its caller.  Expected: no resource findings.

def open_log(path)
  File.open(path, "a")
end

def open_and_check(path)
  f = File.open(path)
  f
end
