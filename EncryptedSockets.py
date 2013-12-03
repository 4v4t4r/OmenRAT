import socket

from EasyEncryption import *

class EncryptedSockException(Exception):
    def __init__(self, value):
        self.value = value
        
    def __str__(self):
        return repr(self.value)

class EncryptedTCPSocket:
    def __init__(self, key, (ip, port)):
        """a base class for AES encrypted sockets."""
        self.key = key
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.listen(5)
        
    def send(self, data):
        """encrypt the data in AES256, then send it over the sock."""
        iv, data = encrypt_aes256(data, self.key)
        send_string = "{0}:{1}".format(iv, data)
        
        self.sock.send(send_string)
        
    def recv(self, data):
        """Receive encrypted data from the socket, decrypt it, and return the decrypted data."""
        response = self.sock.recv(512)
        
        if response == "":
            raise EncryptedSockException("Empty string received.")
        
        iv, data = response.split(":")[0], response.split(":")[1]
        data = decrypt_aes256(data, self.key, iv)
        data = data.strip(" ")
        
        return data

def send_encrypt_data(self, data, key, sock):
    """encrypt the data in AES256, then send it over the socket."""
    iv, data = encrypt_aes256(data, key)  # returns the list [iv, encrypted]

    # since lists cant be sent over sockets, we send it like this.
    send_string = "{0}:{1}".format(iv, data)

    print "Sent: {0}".format(send_string)
    sock.send(send_string)

def receive_decrypt_data(self, key, sock):
    """receive the encrypted data from the socket, decrypt it, and return
    the decrypted data."""
    # take the data and put it back into a list object.
    response = sock.recv(512)
    if response == "":
        raise socket.error
    print "Received: {0}".format(response)

    iv, data = response.split(":")[0], response.split(":")[1]

    # decrypt the data, remember response[0] is the IV.
    data = decrypt_aes256(data, key, iv)
    data = data.strip(" ")
    return data