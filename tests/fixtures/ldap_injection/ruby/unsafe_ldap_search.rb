# Unsafe: tainted Rails param interpolated into the LDAP filter passed to
# Net::LDAP#search.  The receiver is constructed via Net::LDAP.new and
# carries TypeKind::LdapClient; type-qualified resolution rewrites
# `ldap.search` → `LdapClient.search`, firing LDAP_INJECTION.
require "net/ldap"

class UsersController
  def lookup(params)
    ldap = Net::LDAP.new(host: "ldap.example.com")
    user = params[:user]
    filter = "(uid=#{user})"
    ldap.search(base: "ou=people,dc=example,dc=com", filter: filter)
  end
end
