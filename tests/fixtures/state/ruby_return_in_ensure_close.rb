class Reader
  def read_all(path)
    f = File.open(path)
    begin
      return f.read
    ensure
      f.close
    end
  end

  def read_first(path)
    f = File.open(path)
    return f.read
  ensure
    f.close
  end
end
