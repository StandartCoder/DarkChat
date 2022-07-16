class ClientConnection:
    def __init__(self, socketObj, username, encKey):
        self.socketObj = socketObj
        self.username = username
        self.encKey = encKey

    def getIP(self):
        return self.socketObj.getsockname()[0]