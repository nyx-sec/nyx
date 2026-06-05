# Phase 15 — generic instance method on a controller, benign.

class LoginController
  def authenticate(payload)
    unless payload =~ /\A[A-Za-z0-9]{1,32}\z/
      STDOUT.print("invalid\n")
      return "invalid"
    end
    out = `echo hello`
    STDOUT.print(out)
    out
  end
end
