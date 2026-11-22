def current_branch
  `git rev-parse --abbrev-ref HEAD`.strip
end
