class Reader
  def read_all(path)
    f = File.open(path)
    begin
      data = f.read
      return data
    ensure
      puts "done"
    end
  end
end
