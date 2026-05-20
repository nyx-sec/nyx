# Phase 21 — ActionCable benign control.
# class ChatChannel < ApplicationCable::Channel
require 'shellwords'

class ChatChannel
  def receive(data)
    system("echo " + Shellwords.escape(data.to_s))
  end
end
