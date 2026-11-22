class Safe
  COMPONENTS = %w[scheme host port].freeze

  def symbol_first(issue, attributes, user)
    issue.send :safe_attributes=, attributes, user
  end

  def literal_each(uri)
    [:scheme, :host].each do |component|
      uri.send(component)
    end
  end

  def constant_set(uri)
    COMPONENTS.each { |c| uri.send(c) }
  end
end
