class FilesController < ApplicationController
  ROOT = "/srv/files"

  def show
    name = params[:f]
    leaf = File.basename(name)
    send_file File.join(ROOT, leaf)
  end
end
