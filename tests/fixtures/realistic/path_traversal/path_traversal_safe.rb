# Phase 13 path-traversal sanitized (Ruby).  Canonicalises the path via
# `Pathname.new(base).join(name).cleanpath` and validates containment
# with `start_with?(base.to_s)`.  The canonical path is returned as a
# string, never reaching a FILE_IO sink.
require "pathname"

class FilesController
  def show
    name = params[:name]
    base = Pathname.new("/var/data")
    candidate = base.join(name).cleanpath
    raise "escape" unless candidate.to_s.start_with?(base.to_s)
    candidate.to_s
  end
end
