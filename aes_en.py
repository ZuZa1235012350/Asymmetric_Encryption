"""
    Authors:
    Zuzanna Borkowska (s21243)
    Aleksnader Mazurek (s15023)
"""
import base64
import glob

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


class AESCipher:
    """
    AES encryption and decryption class
    """

    def __init__(self, key):
        self.key = key
        """
        Here the key is used directly as iv
        """
        self.iv = key

    def encrypt(self, msg):
        """
        Encryption method
        Method accepts msg (this is the message that will be encrypted)
        and returns the base64 encoded cipher str
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(self.__pad(msg).encode())).decode()

    def decrypt(self, enc):
        """
        Decryption method
        Method accepts enc (this is the encrypted message that will be decrypted)
        and returns he decrypted plaintext str
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.__unpad(cipher.decrypt(base64.b64decode(enc)).decode())

    def __pad(self, text):
        """
        Padding method, encrypted content must be a multiple of 16 bytes
        """
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
       """
       Intercepting the filled characters
       """
       pad = ord(text[-1])
       return text[:-pad]


if __name__ == '__main__':
    """
    Below we randomly generate 16-bit aes key
    """
    cipher = AESCipher(get_random_bytes(16))
    while(True):
        choice = input('Do you want ?\n 1- encrypt \n 2- decrypt \n 3- exit \nfiles?: ')
        """
         The user has a choice of options:
          1: encrypting all files 
          2: decrypt encrypted files
          3: terminate the process
        """
        if choice == '3':
            exit(0)
        if choice == '1':
            for file in glob.glob("test/*.txt"):
                with open(file, "r+") as f:
                    encrypt = cipher.encrypt(f.read())
                    f.seek(0)
                    f.write(encrypt)
        if choice == '2':
            for file in glob.glob("test/*.txt"):
                with open(file, "r+") as f:
                    decrypt = cipher.decrypt(f.read())
                    f.truncate()
                    f.write(decrypt)