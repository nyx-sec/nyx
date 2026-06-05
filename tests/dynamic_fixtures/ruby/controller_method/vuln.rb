# Phase 15 — generic instance method on a controller, vulnerable.
# No framework markers — RubyShape::detect picks ControllerMethod
# from the class+def pair.

class LoginController
  def authenticate(payload)
    STDOUT.print("__NYX_SINK_HIT__\n")
    out = `echo hello #{payload}`
    STDOUT.print(out)
    out
  end
end
