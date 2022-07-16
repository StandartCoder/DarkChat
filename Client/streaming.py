import json
import base64
from encryption import AESEncryption

BUFFERSIZE = 10
PASSWORD = b''
enc = None

def initializeAES(key, VECTOR):
    global PASSWORD
    global enc
    PASSWORD = key
    enc = AESEncryption(PASSWORD, VECTOR)

def createMsg(data):
    if enc != None:
        cipher = enc.generateCipher() 
        encrypted_data = base64.b64encode(cipher.encrypt(data.encode("utf-8")))

        finalMsg = encrypted_data.decode("utf-8")
        finalMsg = f'{len(finalMsg):<10}' + finalMsg

        return finalMsg.encode("utf-8")
    else:
        finalMsg = data
        finalMsg = f'{len(finalMsg):<10}' + finalMsg

        return finalMsg.encode("utf-8")


def streamData(target):
    data = target.recv(BUFFERSIZE)
    if len(data) != 0:
        msglen = int(data[:BUFFERSIZE].strip())
        full_data = b''

        while len(full_data) < msglen:
            full_data += target.recv(BUFFERSIZE)

        if "iv_exc" not in full_data.decode("utf-8") and "key_exc" not in full_data.decode("utf-8"):
            cipher = enc.generateCipher()

            full_data = base64.b64decode(full_data)

            decrypted_data = cipher.decrypt(full_data)

            return decrypted_data
        return full_data
    else:
        pass
