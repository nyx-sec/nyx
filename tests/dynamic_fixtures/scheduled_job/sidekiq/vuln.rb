# Phase 21 (Track M.3) — Sidekiq scheduled-job vuln fixture.
#
# `TickWorker` includes the Sidekiq::Worker mixin (substring marker
# only — the real Sidekiq gem is not loaded).  `perform(payload)`
# splices the payload into a shell command via Kernel#system, the
# classic worker cmdi shape.

# include Sidekiq::Worker
# sidekiq_options queue: :default

class TickWorker
  def self.included_modules
    [:'Sidekiq::Worker']
  end

  def perform(payload)
    # SINK: tainted payload concatenated into shell command.
    system("echo " + payload.to_s)
  end
end
