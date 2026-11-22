def show_log
  ref = ENV['REF']
  system({ 'GIT_PAGER' => 'cat' }, 'git', 'log', ref, chdir: '/srv/repo')
  exec('ls', '-l', ref)
end
