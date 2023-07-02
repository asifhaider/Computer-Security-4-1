# Object Oriented Python will be used throughout the project
# Implementation of AES (Advanced Encryption Standard) algorithm

from bitvector_1805112 import *

class RoundKeysGenerator:
    def __init__(self, key, iteration):
        self.key = key
        self.iteration = iteration
        # create a list of rcon value first byte
        self.first = ["0x01", "0x02", "0x04", "0x08",
                      "0x10", "0x20", "0x40", "0x80", "0x1b", "0x36"]

    def circular_left_shift(self):
        byte_list = self.key[3]
        # circular left shift
        self.shifted = byte_list[1:] + byte_list[:1]
        # print("After circular left shift:", self.shifted)

    def substitue_round_bytes(self):
        self.circular_left_shift()
        self.substituted = [0, 0, 0, 0]
        rcon = [self.first[self.iteration], "0x00", "0x00", "0x00"]
        # use bitvector to substitue bytes
        for i in range(len(self.shifted)):
            b = BitVector(hexstring=self.shifted[i].replace("0x", ""))
            int_val = b.intValue()
            s = Sbox[int_val]
            s = BitVector(intVal=s, size=8)
            # add round constant
            r = BitVector(hexstring=rcon[i].replace("0x", ""))
            int_val = s.intValue() ^ r.intValue()
            # remove the 0x from the hex string
            self.substituted[i] = hex(int_val).replace("0x", "")
        # print("After substitute and round", self.substituted)

    def generate_round_keys(self):
        self.substitue_round_bytes()
        self.round_keys = [0, 0, 0, 0]
        # xor the key[0] with the substituted round bytes
        for i in range(len(self.key[0])):
            b = BitVector(hexstring=self.key[0][i].replace("0x", ""))
            int_val = b.intValue()
            s = BitVector(hexstring=self.substituted[i].replace("0x", ""))
            int_val = int_val ^ s.intValue()
            self.round_keys[i] = hex(int_val).replace("0x", "")

        # make the round keys into 0x format
        for i in range(len(self.round_keys)):
            self.round_keys[i] = "0x" + self.round_keys[i]
        self.key[0] = self.round_keys
        # print(self.key[0])

        # xor the old key[1] with the new key[0]
        # and loop for the rest of the keys
        for i in range(1, len(self.key)):
            self.round_keys = [0, 0, 0, 0]
            for j in range(len(self.key[i])):
                b = BitVector(hexstring=self.key[i][j].replace("0x", ""))
                int_val = b.intValue()
                s = BitVector(hexstring=self.key[i-1][j].replace("0x", ""))
                int_val = int_val ^ s.intValue()
                self.round_keys[j] = hex(int_val).replace("0x", "")
            # make the round keys into 0x format
            for j in range(len(self.round_keys)):
                self.round_keys[j] = "0x" + self.round_keys[j]
            self.key[i] = self.round_keys
        return self.key

