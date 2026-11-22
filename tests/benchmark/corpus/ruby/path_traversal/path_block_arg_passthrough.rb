def write_entry(path, &blk)
  File.open(path, 'wb') { |f| blk.call(f) }
end

def extract(dir, &blk)
  write_entry(File.join(dir, 'entry.bin'), &blk)
end

def handler
  extract(ENV['OUT_DIR']) { |f| f.write('x') }
end
