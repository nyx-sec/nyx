# Phase 21 — Sidekiq benign control.
# include Sidekiq::Worker

require 'shellwords'

class TickWorker
  def perform(payload)
    system("echo " + Shellwords.escape(payload.to_s))
  end
end
