"""
    Authors:
    Zuzanna Borkowska (s21243)
    Aleksnader Mazurek (s15023)
"""
import base64
import glob

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

import config


class RSACipher():
    def encrypt(self, key, raw):
        """
        RSA encryption method
        Method accepts the public key and text for encryption and return encoded ciphertext bytes
        """
        public_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, key, enc):
        """
        RSA decryption method
        Method takes the private key and base64 encoded ciphertext in bytes and returns the decrypted plaintext in bytes
        """
        private_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(base64.b64decode(enc))

    def sign(self, key, text):
        """
        Signature method
        Method takes private key and text for signing bytes and returns message with signature encoded in base64 bytes
        """
        private_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(hash_value)
        return base64.b64encode(signature)

    def verify(self, key, text, signature):
        """
        Signature check method
        Method accepts the public key, the text to be checked and the signature encoded in base64 bytes and returns the result of the signature checking (flag true false)
        """
        public_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(hash_value, base64.b64decode(signature))

if __name__ == '__main__':
    """
        ciper is an object of the above defined class
    """
    cipher = RSACipher()

    while (True):
        """
            The user can choose to encrypt or decrypt all ten files in the test directory
        """
        choice = input('Do you want ?\n 1- encrypt \n 2- decrypt \n 3- exit \nfiles?: ')
        """
            In the following loops each file is opened and when the user:
            a. selects "1" 
            then the text from the file is encrypted, a signature is created and all this data is written to the file.
            b. selects "2":
            then the signature is extracted from the second line of the file and checked for correctness and based on that the encrypted text from the first line is decrypted.
            Then the result of the decryption is written into the file 
            c. selects "3":
            then the process is terminate
        """
        if choice == '3':
            exit(0)
        if choice == '1':
            for file in glob.glob("test/*.txt"):
                with open(file, "r+") as f:
                    encrypt_text = cipher.encrypt(config.Config.SERVER_PUBLIC_KEY, f.read().encode())
                    signature = cipher.sign(config.Config.CLIENT_PRIVATE_KEY, encrypt_text)
                    f.seek(0)
                    f.write(encrypt_text.decode()+ "\n"+ signature.decode())

        if choice == '2':
            for file in glob.glob("test/*.txt"):
                with open(file, "r+") as f:
                    lines = f.readlines()
                    decrypt = cipher.verify(config.Config.CLIENT_PUBLIC_KEY, lines[0].encode(), lines[1].encode())
                    decrypt_text = cipher.decrypt(config.Config.SERVER_PRIVATE_KEY, lines[0].encode())
                    f.write("\nEncypted message: " + decrypt_text.decode())
