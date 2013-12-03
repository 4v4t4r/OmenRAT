import threading
import hashlib
import socket
import select

from EasyEncryption import *

class OmenAdminServer(threading.Thread):
    def __init__(self, port, key, adminkey, server, max_users=5):
        threading.Thread.__init__(self)
        # constants
        self.max_users = max_users
        self.port = port
        self.adminkey = key
        self.key = hashlib.sha256(key).digest()
        self.server = server

        # socket setup
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", port))
        self.sock.listen(5)

        # client managment
        self.descriptors = [self.sock]
        self.clients = {}

        self.client_id = 0

        # commands for administraion
        self.commands = {
            "list": self.cmd_list,
        }

    # Omen Network Protocol
    # All transfer is encrypted in AES256 with randomly generated IV's.
    # *! - from server
    # !* - from client

    # commands
    def cmd_list(self, sock, args):
        if len(args) != 1:
            self.send_encrypt_data("*! invalid args", self.key, sock)
            return

        if args[0] == "admin":
            client_list = self.clients

        elif args[0] == "user":
            client_list = self.server.clients

        else:
            self.send_encrypt_data("*! invalid args", self.key, sock)

        # Display connected users/adminstrators
        self.send_encrypt_data("*! begin")
        try:
            self.send_encrypt_data("{0} connected admin(s)".format(len(client_list.keys())), self.key, sock)
        except IndexError:
            self.send_encrypt_data("0 connected admins", self.key, sock)

        try:
            for id, sock in client_list.iteritems():
                self.send_encrypt_data("ID: {0} ADDR: {2}".format(id, sock.getpeername()[0]), self.key, sock)
        except KeyError:
            print "KeyError"

        self.send_encrypt_data("*! end")

    def remove_connection(self, id, serv):
        print "Removing user {0}...".format(id)
        for c in serv.clients.keys():
            if c == id:
                sock = c
                self.send_encrypt_data("*! conn_close", self.key, sock)
                sock.close()
                try:
                    serv.clients.pop(c)
                    serv.descriptors.remove(c)
                except Exception, e:
                    print "Error removing user\n{0}".format(e)

    def accept_new_connection(self):
        newsock, addr = self.sock.accept()

        print "Admin {0} connected.".format(addr[0])

        self.send_encrypt_data("*! admin_verify", self.key, newsock)
        try:
            response = self.receive_decrypt_data(self.key, newsock)
        except Exception, e:
            print "Socket Error while verifying client {0}\n{1}".format(addr, e)
            return

        # Normal user verification -
        if response == self.adminkey:

            print "Verification of client {0} was successful."
            # Verification successful.
            self.descriptors.append(newsock)
            self.clients[self.client_id] = self.descriptors[-1]
            self.client_id += 1

        else:

            # Verification unsuccessful.
            print "Verification of client {0} was unsuccessful."
            newsock.close()
            return

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
                        data = self.receive_decrypt_data(self.key, sock)
                    except:
                        print "Admin {0} disconnected."
                        sock.close()
                        self.descriptors.remove(sock)

                        for key, value in self.clients.iteritems():

                            if value == sock:
                                self.clients.pop(key)

                        continue

                    if data.startswith("!* "):
                        print "Received command from admin {0}".format(host)
                        data = data.replace("!* ", "")
                        l = data.split(" ")
                        cmd = l[0]
                        args = l[1:]

                        for f in dir(self):

                            if f == "cmd_{0}".format(cmd):

                                f = "{0}({1})".format(f, sock, args)

                                try:
                                    exec f

                                except Exception, e:
                                    print "Failed to process command {0}. Reason:\n{1}".format(cmd, e)
                                    sock.send("*! cmd_invalid")
                    else:
                        print "Recieved unformatted data from admin{0}\n{1}".format(host, data)
                        sock.send("*! cmd_invalid")