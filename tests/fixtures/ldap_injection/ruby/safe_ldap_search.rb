# Safe: Net::LDAP::Filter.escape applies RFC 4515 escaping before the value
# is interpolated into the filter.  Sanitizer(LDAP_INJECTION) clears the cap.
require "net/ldap"

class UsersController
  def lookup(params)
    ldap = Net::LDAP.new(host: "ldap.example.com")
    user = params[:user]
    safe = Net::LDAP::Filter.escape(user)
    filter = "(uid=#{safe})"
    ldap.search(base: "ou=people,dc=example,dc=com", filter: filter)
  end
end
