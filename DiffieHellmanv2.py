import random
import hashlib


def KeyB(A, b, p):
    key_bb = (A ** b) % p
    retB = hashlib.sha256(str(key_bb).encode()).hexdigest()
    return retB


def KeyA(B, a, p):
    key_aa = (B ** a) % p
    retA = hashlib.sha256(str(key_aa).encode()).hexdigest()
    return retA


class DiffieHelman:
    g = int(input("diff g:"))
    p = int(input("diff p:"))

    a = random.randint(5, 10)

    b = random.randint(10, 20)

    A = (g ** a) % p
    B = (g ** b) % p

    # print('g: ', g, ' (a shared value), n: ', p, ' (a prime number)')

    # print('\nAlice calculates:')
    # print('a (Alice random): ', a)
    # print('Alice value (A): ', A, ' (g^a) mod p')

    # print('\nBob calculates:')
    # print('b (Bob random): ', b)
    # print('Bob value (B): ', B, ' (g^b) mod p')

    # print('\nAlice calculates:')
    KeyA(B, a, p)
    # keyA = (B ** a) % p
    #print('Key: ', KeyA, ' (B^a) mod p')
    #print('Key: ', hashlib.sha256(str(KeyA).encode()).hexdigest())

    # print('\nBob calculates:')
    KeyB(A, b, p)

    # keyB = (A ** b) % p
    #print('Key: ', KeyB, ' (A^b) mod p')
    #print('Key: ', hashlib.sha256(str(KeyB).encode()).hexdigest())



