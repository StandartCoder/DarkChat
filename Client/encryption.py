from Crypto.Cipher import AES 
import hashlib
from Crypto import Random
import base64

class AESEncryption:
    def __init__(self, password, vector):
        self.PASSWORD = password
        self.KEY = hashlib.sha256(self.PASSWORD).digest()
        self.IV = base64.b64decode(vector)

        self.MODE = AES.MODE_CFB

    def generateCipher(self):
        return AES.new(self.KEY, self.MODE, IV = self.IV)


class DiffieHellman:
    def __init__(self, sharedBase, sharedPrime):
        self.sharedBase = sharedBase
        self.sharedPrime = sharedPrime