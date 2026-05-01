require 'yaml'

def load_yaml(filename)
  YAML.safe_load(File.read(filename))
end

filename = params[:p]
load_yaml(filename)
