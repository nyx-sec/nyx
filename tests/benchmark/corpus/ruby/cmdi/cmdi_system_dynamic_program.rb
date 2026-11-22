def run_tool(params)
  tool = params[:tool]
  system(tool, "--version")
end
