class Safe
  COMPONENTS = %w[scheme host port].freeze
  OPEN = %w[a b]

  def symbol_first(issue, attributes, user)
    issue.send :safe_attributes=, attributes, user
  end

  def trailing_args(q, from, to)
    q.send(:date_clause, from, to)
  end

  def literal_each(uri, request)
    [:scheme, :host].each do |component|
      uri.send(component)
    end
  end

  def percent_w(p)
    %w(first_page next_page).each { |method| p.send(method) }
  end

  def constant_set(uri)
    COMPONENTS.each { |c| uri.send(c) }
  end

  def extra_arg(obj, name, value)
    obj.send(:set, name, value)
  end
end
