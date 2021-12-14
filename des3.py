"""
    Authors:
    Zuzanna Borkowska (s21243)
    Aleksnader Mazurek (s15023)
"""
import glob
from Cryptodome.Cipher import DES3
from hashlib import md5

class DES3Cipher:
    """
       DES3 encryption and decryption class
    """
    def __init__(self, key):
        """
          Here the key is definded
        """
        tdes_key = DES3.adjust_key_parity(key)
        self.key = tdes_key

    """
      The method encrypts the message in file that is given by file_path according to the defined key 
    """
    def encryptall(self, file_path):
        cipher = DES3.new(self.key, DES3.MODE_EAX, nonce=b'0')
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
            new_file_bytes = cipher.decrypt(file_bytes)
        with open(file_path, 'wb') as output_file:
            output_file.write(new_file_bytes)

    """
       The method decrypts the message in file that is given by file_path according to the defined key 
    """
    def descryptall(self, file_path):
        cipher = DES3.new(self.key, DES3.MODE_EAX, nonce=b'0')
        with open(file_path, 'rb') as input_file:
            file_bytes = input_file.read()
            new_file_bytes = cipher.decrypt(file_bytes)
        with open(file_path, 'wb') as output_file:
            output_file.write(new_file_bytes)

if __name__ == '__main__':
    """
    Creating the class and passing key
    """
    key = "test_passkey"
    key_hash = md5(key.encode('ascii')).digest()  # 16bit hask
    cipher = DES3Cipher(key_hash)
    while True:
        print('choose of the following operations: \n1-Encrypt\n2-Decrypt\n3-exit')
        choice = input("Your choice: ")
        if choice == '3':
            exit(0)
        if choice not in ['1', '2']:
            break

        if choice == '1':
            for file in glob.glob('test/*.txt'):
                cipher.encryptall(file)

        if choice == '2':
            for file in glob.glob('test/*.txt'):
                cipher.descryptall(file)