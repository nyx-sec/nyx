class ChatChannel < ApplicationCable::Channel
  def subscribed
    stream_from "chat_room"
  end

  def receive(data)
    data
  end

  def normalize(data)
    data.to_s
  end
end
