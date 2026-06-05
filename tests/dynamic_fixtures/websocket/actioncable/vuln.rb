# Phase 21 (Track M.3) — Rails ActionCable channel vuln fixture.
#
# `ChatChannel#receive(data)` splices the inbound WebSocket message
# bytes into a shell command via Kernel#system — classic ActionCable
# → cmdi shape.

# class ChatChannel < ApplicationCable::Channel

class ChatChannel
  def receive(data)
    # SINK: tainted data concatenated into shell command.
    system("echo " + data.to_s)
  end
end
