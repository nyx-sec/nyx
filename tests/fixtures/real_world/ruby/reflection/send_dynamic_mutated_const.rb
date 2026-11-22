class Open
  NAMES = %w[a b]
  NAMES << ARGV[0]

  def run(obj)
    NAMES.each { |n| obj.send(n) }
  end

  def param(obj, params)
    params.each { |n| obj.send(n) }
  end
end
