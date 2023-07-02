# implementing the RSA key exchange protocol

import random
import sys, os
sys.path.append(os.path.join(os.path.dirname(sys.path[0]), 'aes_dh'))
from diffie_hellman_1805112 import DiffieHellman

class RSAKeyExchange(DiffieHellman):

    def __init__(self, k):
        # generate 1024 bit safe prime using the self.generate_prime() method
        self.p = self.generate_prime(k)
        self.q = self.generate_prime(k)
        self.n = self.p * self.q
        self.lamda = self.lcm(self.p-1, self.q-1)
        self.e = self.generate_e()
        self.d = self.generate_d()

    def gcd(self, a, b):
        # euclidean algorithm
        while b:
            a, b = b, a % b
        return a
    
    def lcm(self, a, b):
        # least common multiple
        return a * b // self.gcd(a, b)

    # generate e such that 1 < e < lamda and gcd(e, lamda) = 1
    def generate_e(self):
        while True:
            e = random.randrange(2, self.lamda)
            if self.gcd(e, self.lamda) == 1:
                return e
            

    def extended_gcd(self, a, b):
        # extended euclidean algorithm
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)
        
    # generate d such that d*e mod lamda = 1 using the extended euclidean algorithm
    def generate_d(self):
        g, x, y = self.extended_gcd(self.e, self.lamda)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % self.lamda
        
    def get_public_key(self):
        return self.e, self.n
    
    def get_private_key(self):
        return self.d, self.n
    
    def encrypt(self, plaintext, public_key):
        e = self.fast_modular_exponentiation((plaintext), public_key[0], public_key[1])
        return e
    
    def decrypt(self, ciphertext):
        d = self.fast_modular_exponentiation((ciphertext), self.d, self.n)
        return d
        
    def sign(self, plaintext):
        return self.fast_modular_exponentiation(plaintext, self.d, self.n)
    
    def verify(self, ciphertext):
        return self.fast_modular_exponentiation(ciphertext, self.e, self.n)
    
    def shared_secret_key(self, public_key):
        return self.fast_modular_exponentiation(public_key, self.d, self.n)
    

    
# Demo

if __name__ == '__main__':
    
    plaintext = 7261011110810111411511551

    # Alice generates her public and private keys
    alice = RSAKeyExchange(128)
    alice_public_key = alice.get_public_key()

    # Bob generates his public and private keys
    bob = RSAKeyExchange(128)
    bob_public_key = bob.get_public_key()

    print("\033[1;34;40m")

    # print the public and private keys
    print('\nAlice public key:', alice_public_key)
    print('Alice private key:', alice.get_private_key())

    print("\033[1;33;40m")


    print('\nBob public key:', bob_public_key)
    print('Bob private key:', bob.get_private_key())

    # Alice encrypts the plaintext using Bob's public key
    ciphertext = alice.encrypt(plaintext, bob_public_key)

    # Bob decrypts the ciphertext using his private key
    decrypted_plaintext = bob.decrypt(ciphertext)
    print("\033[1;32;40m")
    print('Plaintext:', plaintext)

    print("\033[1;31;40m")

    # print the ciphertext and decrypted plaintext
    print('\nCiphertext:', ciphertext)
    print("\033[1;32;40m")
    print('Decrypted Text:', decrypted_plaintext)

