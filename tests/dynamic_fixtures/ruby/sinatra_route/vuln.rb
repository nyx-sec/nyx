# Phase 15 — Sinatra route, vulnerable.
# Reads payload (passed by harness via block argument) and pipes through /bin/sh.
# Entry: route block  Cap: CODE_EXEC

# nyx-shape: sinatra
get '/run' do |payload|
  STDOUT.print("__NYX_SINK_HIT__\n")
  out = `echo hello #{payload}`
  STDOUT.print(out)
  out
end
