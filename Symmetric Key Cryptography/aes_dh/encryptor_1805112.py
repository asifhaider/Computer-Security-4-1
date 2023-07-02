from key_generator_1805112 import *

class EncryptionCycle:
    def __init__(self, user_io):
        self.plaintext_blocks = user_io.plaintext_to_matrix()
        self.keys = user_io.all_keys
        self.cipher_matrix = []
        self.cipher_text = ""
        self.state_matrix = [[] for i in range(len(self.plaintext_blocks))]

    def reorder_column_major_matrix(self, matrix):
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
        for i in range(len(self.plaintext_blocks)):
            self.state_matrix[i] = self.reorder_column_major_matrix(self.plaintext_blocks[i])
        round_zero_key = self.reorder_column_major_matrix(self.keys[0])

        for j in range(len(self.state_matrix)):
        # elementwise XOR between state matrix and round zero key
            for i in range(len(self.state_matrix[j])):
                self.state_matrix[j][i] = hex(int(self.state_matrix[j][i], 16) ^ int(round_zero_key[i], 16))
        
        for j in range(len(self.state_matrix)):
        # remove the 0x from the hex values
            for i in range(len(self.state_matrix[j])):
            # if single digit, then add a leading 0
                if len(self.state_matrix[j][i]) == 3:
                    self.state_matrix[j][i] = self.state_matrix[j][i][:2] + "0" + self.state_matrix[j][i][2:]
                self.state_matrix[j][i] = self.state_matrix[j][i][2:]

        # print("State matrix: ", self.state_matrix)

    def substitute_bytes(self):
        # use bitvector to substitue bytes
        for j in range(len(self.state_matrix)):
            for i in range(len(self.state_matrix[j])):
                b = BitVector(hexstring=self.state_matrix[j][i].replace("0x", ""))
                int_val = b.intValue()
                s = Sbox[int_val]
                s = BitVector(intVal=s, size=8)
                self.state_matrix[j][i] = hex(s.intValue()).replace("0x", "")
        # print("After substitute bytes: ", self.state_matrix)

    def shift_rows(self):

        for j in range(len(self.state_matrix)):
        # left shift the rows of the state matrix, 1st row by 0, 2nd row by 1, 3rd row by 2, 4th row by 3
        # 2nd row 
            self.state_matrix[j][4], self.state_matrix[j][5], self.state_matrix[j][6], self.state_matrix[j][7] = self.state_matrix[j][5], self.state_matrix[j][6], self.state_matrix[j][7], self.state_matrix[j][4]
            # 3rd row
            self.state_matrix[j][8], self.state_matrix[j][9], self.state_matrix[j][10], self.state_matrix[j][11] = self.state_matrix[j][10], self.state_matrix[j][11], self.state_matrix[j][8], self.state_matrix[j][9]
            # 4th row
            self.state_matrix[j][12], self.state_matrix[j][13], self.state_matrix[j][14], self.state_matrix[j][15] = self.state_matrix[j][15], self.state_matrix[j][12], self.state_matrix[j][13], self.state_matrix[j][14]

        # print("After shift rows: ", self.state_matrix)

    def mix_columns(self):
        # use Mixer from bitvector 
        # declare a 4x4 matrix
        for l in range(len(self.state_matrix)):
            self.mixed = [0 for i in range(16)]
            for i in range (4):
                for j in range(4):
                    for k in range(4):
                        bv1 = Mixer[i][k]
                        bv2 = BitVector(hexstring=self.state_matrix[l][4*k+j].replace("0x", ""))
                        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                        # xor all the bv3 values
                        if k == 0:
                            result = bv3
                        else:
                            result = result ^ bv3
                    # print ("result: ", result.getHexStringFromBitVector())
                    self.mixed[4*i+j] = result.getHexStringFromBitVector()
            self.state_matrix[l] = self.mixed
        # print("After mix columns: ", self.state_matrix)
        
    def add_round_key(self, iteration):
        self.rounded = [0 for i in range(16)]
        # element wise xor with the key[iteration]
        for j in range(len(self.state_matrix)):
        # add 0x to the state matrix
            for i in range(len(self.state_matrix[j])):
                self.state_matrix[j][i] = "0x" + self.state_matrix[j][i]
        # print ("Key: ", self.keys[1])
        # print ("State matrix: ", self.state_matrix)

        # reorder keys to column major
        round_one_key = self.reorder_column_major_matrix(self.keys[iteration+1])

        for j in range(len(self.state_matrix)):
        # elementwise XOR between state matrix and round zero key
            for i in range(len(self.state_matrix[j])):
                self.state_matrix[j][i] = hex(int(self.state_matrix[j][i], 16) ^ int(round_one_key[i], 16))
        
        # remove the 0x from the hex values
        for j in range(len(self.state_matrix)):
            for i in range(len(self.state_matrix[j])):
                # if single digit, then add a leading 0
                if len(self.state_matrix[j][i]) == 3:
                    self.state_matrix[j][i] = self.state_matrix[j][i][:2] + "0" + self.state_matrix[j][i][2:]
                self.state_matrix[j][i] = self.state_matrix[j][i][2:]

        # print("After add round key: ", self.state_matrix)
