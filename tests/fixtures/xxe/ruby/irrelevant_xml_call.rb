# Baseline: tainted body flows through a non-parser string operation.
# No XML parser entry point, no XXE label classification.
require "sinatra"

get "/wrap" do
  body = params[:xml]
  "<wrap>#{body}</wrap>"
end
