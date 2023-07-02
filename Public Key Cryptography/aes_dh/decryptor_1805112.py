from encryptor_1805112 import *

class DecryptionCycle:
    def __init__(self, user_io):
        self.ciphertext_blocks = user_io.ciphertext_to_matrix()
        self.keys = user_io.all_keys
        self.plaintext = ""
        self.state_matrix = [[] for i in range(len(self.ciphertext_blocks))]

    def get_state_matrix(self):
        return self.state_matrix

    def reorder_column_major(self, matrix):
        new_matrix = []
        for i in range(4):
            for j in range(4):
                new_matrix.append(matrix[j][i])
        return new_matrix

    def list_to_matrix(self, list):
        matrix = []
        for i in range(0, len(list), 4):
            matrix.append(list[i:i+4])
        return matrix

    def hex_to_ascii(self, hex_list):
        ascii_list = []
        for i in range(len(hex_list)):
            ascii_list.append(chr(int(hex_list[i], 16)))
        return ascii_list

    def create_state_matrix(self):
        for i in range(len(self.ciphertext_blocks)):
            self.state_matrix[i] = self.reorder_column_major(self.ciphertext_blocks[i])
        round_ten_key = self.reorder_column_major(self.keys[10])

        for j in range(len(self.state_matrix)):
        # elementwise XOR between state matrix and round ten key
            for i in range(len(self.state_matrix[j])):
                self.state_matrix[j][i] = hex(int(self.state_matrix[j][i], 16) ^ int(round_ten_key[i], 16))

        for j in range(len(self.state_matrix)):
        # remove the 0x from the hex values
            for i in range(len(self.state_matrix[j])):
            # if single digit, then add a leading 0
                if len(self.state_matrix[j][i]) == 3:
                    self.state_matrix[j][i] = self.state_matrix[j][i][:2] + "0" + self.state_matrix[j][i][2:]
                self.state_matrix[j][i] = self.state_matrix[j][i][2:]

        # print("State matrix: ", self.state_matrix)

    def inverse_shift_rows(self):
        for j in range(len(self.state_matrix)):
        # right shift the rows of the state matrix, 1st row by 0, 2nd row by 1, 3rd row by 2, 4th row by 3
            self.state_matrix[j][4], self.state_matrix[j][5], self.state_matrix[j][6], self.state_matrix[j][7] = self.state_matrix[j][7], self.state_matrix[j][4], self.state_matrix[j][5], self.state_matrix[j][6]
            self.state_matrix[j][8], self.state_matrix[j][9], self.state_matrix[j][10], self.state_matrix[j][11] = self.state_matrix[j][10], self.state_matrix[j][11], self.state_matrix[j][8], self.state_matrix[j][9]
            self.state_matrix[j][12], self.state_matrix[j][13], self.state_matrix[j][14], self.state_matrix[j][15] = self.state_matrix[j][13], self.state_matrix[j][14], self.state_matrix[j][15], self.state_matrix[j][12]

        # print("After inverse shift rows: ", self.state_matrix)

    def inverse_substitute_bytes(self):
        for j in range(len(self.state_matrix)):
        # use bitvector InvSbox to substitute bytes
            for i in range(len(self.state_matrix[j])):
                b = BitVector(hexstring=self.state_matrix[j][i].replace("0x", ""))
                val = b.intValue()
                s = InvSbox[val]
                s = BitVector(intVal=s, size=8)
                self.state_matrix[j][i] = hex(s.intValue()).replace("0x", "")

        # print("After inverse substitute bytes: ", self.state_matrix)

    
    def add_round_key(self, iteration):
        self.rounded = [0 for i in range(16)]
        # add 0x to the state matrix
        for j in range(len(self.state_matrix)):
            for i in range(len(self.state_matrix[j])):
                self.state_matrix[j][i] = "0x" + self.state_matrix[j][i]
        # print ("Key: ", self.keys[1])
        # print ("State matrix: ", self.state_matrix)

        # reorder keys to column major
        round_nine_key = self.reorder_column_major(self.keys[10-iteration-1])

        # elementwise XOR between state matrix and round zero key
        for j in range(len(self.state_matrix)):
            for i in range(len(self.state_matrix[j])):
                self.state_matrix[j][i] = hex(int(self.state_matrix[j][i], 16) ^ int(round_nine_key[i], 16))
        
        # remove the 0x from the hex values
        for j in range(len(self.state_matrix)):
            for i in range(len(self.state_matrix[j])):
                # if single digit, then add a leading 0
                if len(self.state_matrix[j][i]) == 3:
                    self.state_matrix[j][i] = self.state_matrix[j][i][:2] + "0" + self.state_matrix[j][i][2:]
                self.state_matrix[j][i] = self.state_matrix[j][i][2:]

        # print("After add round key: ", self.state_matrix)

    def inverse_mix_column(self):
        for l in range(len(self.state_matrix)):
        # use InvMixer from BitVector to mix columns
            self.mixed = [0 for i in range(16)]
            for i in range(4):
                for j in range(4):
                    for k in range(4):
                        bv1 = InvMixer[i][k]
                        bv2 = BitVector(hexstring=self.state_matrix[l][k*4+j].replace("0x", ""))
                        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                        if k == 0:
                            result = bv3
                        else:
                            result = result ^ bv3
                    self.mixed[4*i+j] = result.getHexStringFromBitVector()

            self.state_matrix[l] = self.mixed
        # print("After inverse mix column: ", self.state_matrix[l])

