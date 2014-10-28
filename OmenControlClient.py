import socket
import hashlib
import threading
import Tkinter, tkMessageBox

from EasyEncryption import *
from EncryptedSockets import *

__version__ = 0.1
__author__ = "Kaonashi"

"""
The admin client for controlling your OmenServer.
"""

class OmenAdminClient(threading.Thread):
    def __init__(self, port, aes_key, admin_key, use_gui=True, gui_window=None):
        threading.Thread.__init__(self)
        # Constant Vars
        self.debug = True

        self.use_gui = use_gui
        self.win = gui_window

        self.port = port
        self.aes_key = hashlib.sha256(aes_key).digest()
        self.admin_key = admin_key

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        self.printf("OmenAdminClient started.")

        try:
            self.sock.connect((self.remote_addr, self.remove_port))
        except Exception, e:
            self.printf("Error connecting")
            self.printf(e, debug=True)

        while True:
            # Attempt to receive command from server
            try:
                data = receive_decrypt_data(self.key, self.sock)
            except Exception, e:
                self.printf("Error receiving")
                self.printf(e, debug=True)
                continue
            else:
                if data == "":
                    self.printf("Error receiving")
                    self.printf("empty string", debug=True)
                    # Since an empty string usually means a socket error
                    # kill the loop
                    break
                elif data.startswith("*! "):
                    data = data.replace("*! ", "")

                    cmd = data.split(" ")[0]
                    args = data.split(" ")

                    del args[0]

                    self.printf("Received command from server...")
                    self.printf("Running command {0}...".format(cmd))

                    try:
                        self.commands[cmd](args)
                    except KeyError:
                        self.printf("Command {0} does not exist.".format(cmd))
                        send_encrypt_data("!* cmd_invalid")

                else:
                    self.printf("Received unformatted data from server")





    def printf(self, string, debug=False):
        if debug:
            if not self.debug:
                return

        if self.use_gui:
            self.win.console_text.insert(Tkinter.END, "{0}\n".format(string))
        else:
            print string


if __name__ == "__main__":
    pass