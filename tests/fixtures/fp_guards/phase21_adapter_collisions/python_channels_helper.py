from channels.generic.websocket import WebsocketConsumer


class ChatConsumer(WebsocketConsumer):
    def receive(self, text_data=None, bytes_data=None):
        return text_data


def normalize_frame(text_data):
    return str(text_data)
