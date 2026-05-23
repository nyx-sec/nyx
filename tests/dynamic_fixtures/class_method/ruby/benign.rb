# Phase 19 (Track M.1) — class-method benign control for Ruby.
require 'shellwords'

class UserService
  def initialize
  end

  def run(input)
    `true #{Shellwords.escape(input)}`
  end
end
