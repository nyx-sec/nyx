# `is_open` / `reopen` are not acquires.  IO.popen is, and leaks here.
# Expected: exactly one state-resource-leak (pipe_leak).

def check(door)
  st = door.is_open
  puts st
end

def again(log)
  r = log.reopen
  puts r
end

def pipe_leak(cmd)
  io = IO.popen(cmd)
  puts io.read
end
