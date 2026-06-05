import socketio

sio = socketio.Server()


@sio.on("message")
def message(sid, data):
    return data


def normalize(data):
    return str(data)
