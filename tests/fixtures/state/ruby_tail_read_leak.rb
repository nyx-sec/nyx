# The method returns the contents, not the file.  Expected:
# state-resource-leak.
def slurp(path)
  f = File.open(path)
  f.read
end
