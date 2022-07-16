import socket
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random

IV = None

def generateVector():
    global IV

    if IV == None:
        IV = Random.new().read(AES.block_size)

    return base64.b64encode(IV)

class AESEncryption:
    def __init__(self, password):
        self.PASSWORD = password
        self.KEY = hashlib.sha256(self.PASSWORD).digest()

        self.MODE = AES.MODE_CFB

    def generateCipher(self):
        return AES.new(self.KEY, self.MODE, IV = IV)