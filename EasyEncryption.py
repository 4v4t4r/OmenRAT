import os
from Crypto.Cipher import AES

__version__ = 0.2
__author__ = "KaonashiHF"

"""A high level interface for encrypting and decrypting strings with AES256."""

def check_string(string, chunk_size=16):
    """Prepare string for encryption. Will pad, or split into a list if needed."""

    if len(string) == chunk_size:
        # String is already the chunk size
        return string

    elif len(string) < chunk_size:
        # string is less than the chunk size,
        # pad string with spaces.
        string = string.ljust(chunk_size)
        return string

    elif len(string) > chunk_size:
        # string is more than the chunk_size,
        # split string into chunks, make sure
        # they are padded and return a list.

        strings = [string[i:i+chunk_size] for i in range(0, len(string), chunk_size)]
        i = 0
        for s in strings:
            if len(s) < chunk_size:
                strings[i] = s.ljust(chunk_size)
            i += 1
        return strings


def encrypt_aes256(data, key, iv="random"):
    """returns the data given encrypted with aes256, with the key given"""

    data = check_string(data)

    # Handle a list
    if type(data) == list:
        strings = []
        for string in data:
            if iv == "random":
                iv = os.urandom(16)
            encryptor = AES.new(key, AES.MODE_CBC, iv)
            strings.append([iv, encryptor.encrypt(string)])
        return strings

    # Handle a 16 char string
    else:
        if iv == "random":
            iv = os.urandom(16)
            encryptor = AES.new(key, AES.MODE_CBC, iv)
            return iv, encryptor.encrypt(data)
        elif type(iv) == str:
            if len(iv) != 16:
                raise TypeError, "IV must be 16 chars"


def decrypt_aes256(data, key, iv):
    """decrypts the data from aes256, with the key given"""
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    return decryptor.decrypt(data)