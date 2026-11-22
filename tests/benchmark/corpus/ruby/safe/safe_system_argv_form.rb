def show_log
  ref = ENV['REF']
  system('git', 'log', ref)
  system('git', 'log', ref, chdir: '/srv/repo')
end
