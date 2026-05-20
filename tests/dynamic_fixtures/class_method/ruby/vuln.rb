# Phase 19 (Track M.1) — class-method vuln fixture for Ruby.
#
# UserService#run pipes user input into a shell, classic OS command
# injection.  Default `.new` ctor — no mock deps needed.
class UserService
  def initialize
  end

  def run(input)
    # SINK: tainted input → shell
    `echo #{input}`
  end
end
