# Phase 13 path-traversal positive (Ruby).  Rails-shape controller
# reads `params[:name]` (Source) and interpolates it into the path
# argument of `File.write` (new FILE_IO sink in `src/labels/ruby.rs`).
class FilesController
  def update
    name = params[:name]
    File.write("/var/data/#{name}", "data")
  end
end
