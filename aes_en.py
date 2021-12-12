"""
    Authors:
    Zuzanna Borkowska (s21243)
    Aleksnader Mazurek (s15023)
"""
import pyAesCrypt
import glob

"""
    This method accepts the key and the content to be encrypted according to it. 
    It returns the content with the extension ".crypted".
"""
def encrypt(key, source):
    output = source + ".crypted"
    pyAesCrypt.encryptFile(source, output, key)
    return output

"""
    This method accepts the key and the content to be decrypted according to it. 
    It returns the content without the extension ".crypted".
"""
def decrypt(key, source):
    dfile = source.split(".")
    output = dfile[0] + "decrypted." + dfile[1]
    pyAesCrypt.decryptFile(source, output, key)
    return


key = "test_passkey"

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
        for file in glob.glob('test/*.txt'):
            encrypt(key, file)
            print("done")
    if choice == '2':
        for file in glob.glob('test/*.crypted'):
            decrypt(key, file)
            print("done")