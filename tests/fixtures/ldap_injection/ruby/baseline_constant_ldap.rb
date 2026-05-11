# Baseline: filter is a literal string, no taint reaches the search call.
require "net/ldap"

class UsersController
  def lookup
    ldap = Net::LDAP.new(host: "ldap.example.com")
    ldap.search(base: "ou=people,dc=example,dc=com", filter: "(objectClass=person)")
  end
end
