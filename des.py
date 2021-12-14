"""
    Authors:
    Zuzanna Borkowska (s21243)
    Aleksnader Mazurek (s15023)
"""
from Cryptodome.Cipher import DES
import glob
import re
from secrets import token_bytes

ciphertext_tab = []
nonce_tab = []
tag_tab = []
"""
    The method takes the message and according to the key defined above encrypts it using DES
"""
class DESCipher:
    """
    DES encryption and decryption class
    """
    def __init__(self, key):
        """
          Here the key is definded
        """
        self.key = key

    """
       The method encrypts the message (msg) according to the defined key 
    """
    def encrypt(self, msg):
        cipher = DES.new(self.key, DES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
        return nonce, ciphertext, tag

    """
        The method decrypts the encrypted message (cipertext) according to the defined key 
    """
    def decrypt(self, nonce, ciphertext, tag):
        cipher = DES.new(self.key, DES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        try:
            cipher.verify(tag)
            return plaintext.decode('ascii')
        except:
            return False


if __name__ == '__main__':
    cipher = DESCipher(token_bytes(8))
    while True:
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
                    nonce, ciphertext, tag = cipher.encrypt(f.read())
                    ciphertext_tab.append(ciphertext)
                    nonce_tab.append(nonce)
                    tag_tab.append(tag)
                    f.seek(0)
                    f.write(re.sub('[^a-zA-Z0-9 \n\.]', '', ciphertext.__str__()))

        if choice == '2':
            i = 0
            for file in glob.glob("test/*.txt"):
                with open(file, "r+") as f:
                    nonce = nonce_tab[i]
                    tag = tag_tab[i]
                    ciphertext = ciphertext_tab[i]
                    plaintext = cipher.decrypt(nonce, ciphertext , tag)
                    f.truncate()
                    f.write(plaintext)
                    i+= 1