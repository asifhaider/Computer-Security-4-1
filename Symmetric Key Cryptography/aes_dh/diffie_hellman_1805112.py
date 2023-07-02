import random
import time
import pandas as pd

class DiffieHellman:
    def __init__(self):
        pass

    def set_modulus(self, p):
        self.p = p

    # fast modular exponentiation function
    def fast_modular_exponentiation(self, a, b, n):
        # a^b mod n
        result = 1
        if 1 & b:
            result = a
        while b:
            b >>= 1
            a = (a*a) % n
            if 1 & b:
                result = (result*a) % n
        return result

    # miller rabin primality test: verification of large primes
    def is_prime(self, n, iter):
        if n < 4:
            return n == 2 or n == 3

        r, s = 0, n-1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(iter):
            a = random.randrange(2, n-1)
            x = self.fast_modular_exponentiation(a, s, n)
            if x == 1 or x == n-1:
                continue
            for _ in range(r-1):
                x = self.fast_modular_exponentiation(x, 2, n)
                if x == n-1:
                    break
            else:
                return False
        return True

    # a faster method for generating a safe prime
    def generate_prime(self, k):
        # at least how many bits long the large prime number should be

        while True:
            q = random.randrange(int(2**(k-1)), int(2**k))
            if self.is_prime(q, 50):
                p = 2*q + 1
                if self.is_prime(p, 50):
                    return p

    # primitive root checker
    def is_primitive_root(self, g):
        # check if g^2 mod p is not 1
        if self.fast_modular_exponentiation(g, 2, self.p) == 1:
            return False
        # check if g^((p-1)/2) mod p is not 1
        if self.fast_modular_exponentiation(g, (self.p-1)//2, self.p) == 1:
            return False
        return True

    # find a generator of that prime number (primitive root finder)
    def find_generator(self, min, max):
        # find a random number between min and max
        g = random.randrange(min, max)
        while not self.is_primitive_root(g):
            g = random.randrange(min, max)
        return g

    def compute_key(self, g, x):
        return self.fast_modular_exponentiation(g, x, self.p)


if __name__ == "__main__":

    p_values = []
    p_avg = []
    g_values = []
    g_avg = []
    a_b_values = []
    a_b_avg = []
    A_B_values = []
    A_B_avg = []
    s1_s2_values = []
    s1_s2_avg = []
    
    iterations = 5
    for k in [128, 192, 256]:
        for i in range(iterations):
            
            print("\n============================= " + str(k) + ": iteration " + str(i+1) + " =======================================\n")

            diffie_hellman = DiffieHellman()

            # timstamp
            modulus_start = time.time()
            p = diffie_hellman.generate_prime(k)
            modulus_end = time.time()
            print("Public Modulus:", p)
            diffie_hellman.set_modulus(p)

            generator_start = time.time()
            g = diffie_hellman.find_generator(2, p-2)
            generator_end = time.time()
            print("Primitive Root:", g)

            # Two more primes a and b both at least (k/2) bits long
            a_start = time.time()
            a = diffie_hellman.generate_prime(k/2)
            a_end = time.time()
            b_start = time.time()
            b = diffie_hellman.generate_prime(k/2)
            b_end = time.time()
            print("Alice's Private Key:", a)
            print("Bob's Private Key:", b)

            # Alice and Bob compute their public keys
            A_start = time.time()
            A = diffie_hellman.compute_key(g, a)
            A_end = time.time()
            B_start = time.time()
            B = diffie_hellman.compute_key(g, b)
            B_end = time.time()
            print("Alice's Public Key:", A)
            print("Bob's Public Key:", B)

            # Alice and Bob compute their shared secret key
            s1_start = time.time()
            s1 = diffie_hellman.compute_key(A, b)
            s1_end = time.time()
            s2_start = time.time()
            s2 = diffie_hellman.compute_key(B, a)
            s2_end = time.time()
            print("Alice's Shared Secret Key:", s1)
            print("Bob's Shared Secret Key:", s2)

            # save the values in a list to create a dataframe later
            p_values.append(modulus_end-modulus_start)
            g_values.append(generator_end-generator_start)
            a_b_values.append(a_end-a_start+b_end-b_start)
            A_B_values.append(A_end-A_start+B_end-B_start)
            s1_s2_values.append(s1_end-s1_start+s2_end-s2_start)

        # take the average of the values and discard the originals
        p_avg.append(sum(p_values)/len(p_values))
        g_avg.append(sum(g_values)/len(g_values))
        a_b_avg.append(sum(a_b_values)/(len(a_b_values)*2))
        A_B_avg.append(sum(A_B_values)/(len(A_B_values)*2))
        s1_s2_avg.append(sum(s1_s2_values)/(len(s1_s2_values)*2))
    
    # blue color
    print("\033[1;34;40m")
    print("\n================================== Report (" + str(iterations) + " trials) =========================================\n")
    # create a dictionary to create a dataframe
    data = {'p': p_avg, 'g': g_avg, 'a or b': a_b_avg, 'A or B': A_B_avg, 'shared key': s1_s2_avg}
    df = pd.DataFrame(data, index=['128', '192', '256'])
    
    # beautify the dataframe as a visual table
    df.index.name = 'k (bits)'
    df.columns.name = 'Time (seconds)'
    print(df)
    print("\n==============================================================================================")
    
