# Phase 15 — Sinatra route, benign.
# Validates payload then runs a fixed echo.

# nyx-shape: sinatra
get '/run' do |payload|
  unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
    STDOUT.print("invalid\n")
    next "invalid"
  end
  out = `echo hello`
  STDOUT.print(out)
  out
end
