# Phase 19 (Track M.1) — class-method benign control for Ruby.
require 'shellwords'

class UserService
  def initialize
  end

  def run(input)
    `echo #{Shellwords.escape(input)}`
  end
end
