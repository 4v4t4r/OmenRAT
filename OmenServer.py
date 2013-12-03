import socket
import select
import hashlib
import sys
import threading
import ConfigParser

from OmenAdminServer import OmenAdminServer
from EasyEncryption import *
from EncryptedSockets import *
from confighelpers import *

__author__ = "Kaonashi (hackforums)"
__version__ = "0.3a"

"""
a new kind of remote administration tool
"""

# constants
READ_SIZE = 512

class OmenServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

        print "OmenServer starting..."

        self.config_init()
        self.key = hashlib.sha256(self.key).digest()

        # setting up the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.port))
        self.sock.listen(5)

        # client handling
        self.descriptors = [self.sock]
        self.clients = {}

        self.client_id = 0

        print "OmenServer started on port {0}".format(self.port)
        print "OmenAdminServer starting..."
        self.admin_server = OmenAdminServer(self.admin_port, self.key,
                                            self.admin_key, self, self.admin_max_users)

        self.admin_server.start()
        print "OmenAdminServer started on port {0}".format(self.admin_port)

    def config_init(self):
        self.config = ConfigParser.ConfigParser()

        try:
            self.config.read("{0}\\OmenConfig.cfg".format(os.getcwd()))
        except IOError, e:
            print "WARNING: ERROR READING CONFIG FILE\n{0}\nUSING DEFAULT!".format(e)
            self.key = "samplekey"
            self.port = 9001
            self.admin_port = 9002
            self.admin_max_users = 5
            self.admin_key = "password"

        self.key = ConfigSectionMap(self.config, "Encryption")["aes_key"]
        self.port = int(ConfigSectionMap(self.config, "Network")["port"])
        self.admin_port = int(ConfigSectionMap(self.config, "Network")["admin_port"])
        self.admin_max_users = int(ConfigSectionMap(self.config, "Admin")["admin_max_users"])
        self.admin_key = (ConfigSectionMap(self.config, "Admin")["admin_key"])

    def run(self):
        while True:
            # wait for an event on a readable socket descriptor..
            (sread, swrite, sexc) = select.select(self.descriptors, [], [])

            # iterate through tagged read descriptors
            for sock in sread:

                if sock == self.sock:
                    # if we get a response on the server socket
                    self.accept_new_connection()

                else:
                    host, port = sock.getpeername()

                    try:
                        data = receive_decrypt_data(self.key, sock)
                    except:
                        sock.close()
                        self.descriptors.remove(sock)

                        for key, value in self.clients.iteritems():

                            if value == sock:
                                self.clients.pop(key)

                        continue

                    if data.startswith("!* "):
                        print "Received command from client {0}".format(host)
                    else:
                        print "Recieved unformatted data from client{0}\n{1}".format(host, data)

    def accept_new_connection(self):
        newsock, addr = self.sock.accept()

        print "Client connected. {0}".format(addr[0])

        send_encrypt_data("*! verify", self.key, newsock)
        try:
            response = receive_decrypt_data(self.key, newsock)
        except Exception, e:
            print "Socket Error while verifying client {0}\n{1}".format(addr, e)
            return

        # Normal user verification -
        if response == "!* correct":
            print "Verification of client {0} was successful."
            # Verification successful.
            self.descriptors.append(newsock)
            self.clients[self.client_id] = self.descriptors[-1]
            self.client_id += 1

        else:
            # Verification unsuccessful.
            print "Verification of client {0} was unsuccessful."
            newsock.close()


if __name__ == "__main__":
    server = OmenServer()
    server.start()