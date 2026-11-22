require 'sinatra'

def write_entry(path, &blk)
  File.open(path, 'wb') { |f| blk.call(f) }
end

def extract(dir, &blk)
  write_entry(File.join('/var/out', 'entry.bin'), &blk)
end

get '/extract' do
  extract(params[:dir]) { |f| f.write('x') }
end
