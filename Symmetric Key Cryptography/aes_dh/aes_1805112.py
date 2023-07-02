import time, os, sys
from decryptor_1805112 import *

class UserIO:
    def __init__(self, key, plaintext):
        self.padding_constant = " "
        self.padded_value = 0

        # keep only the first 16 characters of the key

        self.actual_key = key
        self.input_key = self.key_check(key) if key is not None else None
        self.input_plaintext = plaintext
        self.plaintext_blocks = self.process_plaintext(self.input_plaintext)
        # print("Input plaintext: ", self.plaintext_blocks)
        self.cipher_text = ""
        self.deciphered_text = ""
        
        
    def process_plaintext(self, plaintext):
        # divide into 16 character blocks
        # append 0s to any block that is less than 16 characters
        if plaintext is None:
            return None
        
        # print ("Padded value: ", self.padded_value)
        if len(plaintext) % 16 != 0:
            self.padded_value = 16 - (len(plaintext) % 16)
            plaintext += self.padding_constant * self.padded_value
            # save the padded value for later use
        # print("Plain Text Here: ", plaintext)

        return [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    
    def process_ciphertext(self, ciphertext):
        # divide into 16 character blocks
        # append 0s to any block that is less than 16 characters
        # print ("Padded value: ", self.padded_value)
        if len(ciphertext) % 16 != 0:
            ciphertext += self.padding_constant * self.padded_value
            # save the padded value for later use

        # print("Cipher Text Here: ", ciphertext)

        return [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    
    def process_deciphered_text(self):
        # remove the padded value from the deciphered text
        # print("Padded value: ", self.padded_value)
        if self.padded_value != 0:
            self.deciphered_text = self.deciphered_text[:-self.padded_value]
        # print("Deciphered text Here: ", self.deciphered_text)

    def key_check(self, key):
        # if greater than 16 characters, then keep only the first 16 characters
        if len(key) > 16:
            return key[:16]
        # if less than 16 characters, then append 0s to make it 16 characters
        elif len(key) < 16:
            return key + self.padding_constant * (16 - len(key))
        else:
            return key
    
    def set_cipher_text(self, cipher_text):
        self.cipher_text = cipher_text
        self.ciphertext_blocks = self.process_ciphertext(self.cipher_text)

    def set_deciphered_text(self, deciphered_text):
        self.deciphered_text = deciphered_text

    def print_input(self):
        # colorized print
        print("\033[1;32;40m")
        print("Plaintext: ", self.input_plaintext)
        print("Key: ", self.input_key)

    def return_input(self):
        return self.input_plaintext, self.input_key

    def plaintext_to_hex(self):
        # output format: list of he and then converted to int
        return [hex(ord(c)) for c in self.input_plaintext]

    def plaintext_blocks_to_hex(self):
        hex_block = self.plaintext_blocks.copy()
        # output format: list of hex and then converted to int
        for i in range(len(self.plaintext_blocks)):
            # print (self.plaintext_blocks[i])
            hex_block[i] = [hex(ord(c)) for c in self.plaintext_blocks[i]]
        return hex_block

    def ciphertext_blocks_to_hex(self):
        hex_block = self.ciphertext_blocks.copy()
        # output format: list of hex and then converted to int
        for i in range(len(self.ciphertext_blocks)):
            # print (self.ciphertext_blocks[i])
            hex_block[i] = [hex(ord(c)) for c in self.ciphertext_blocks[i]]
        return hex_block        

    def key_to_hex(self, key):
        # output format: list of he and then converted to int
        if key is None:
            print("Key is not set")
            exit()
        return [hex(ord(c)) for c in key]

    # divide the hex list into blocks of 4x4 matrix
    def plaintext_to_matrix(self):
        hex_list = self.plaintext_blocks_to_hex()
        # print(hex_list)
        matrix = [[] for i in range(len(hex_list))]
        for j in range(len(hex_list)):
            for i in range(0, len(hex_list[j]), 4):
                matrix[j].append(hex_list[j][i:i+4])
        return matrix
    
    def ciphertext_to_matrix(self):
        hex_list = self.ciphertext_blocks_to_hex()
        # print(hex_list)
        matrix = [[] for i in range(len(hex_list))]
        for j in range(len(hex_list)):
            for i in range(0, len(hex_list[j]), 4):
                matrix[j].append(hex_list[j][i:i+4])
        return matrix

    
    def ciphertext_to_hex(self):
        # output format: list of he and then converted to int
        return [hex(ord(c)) for c in self.cipher_text]
        
    def deciphered_text_to_hex(self):
        # output format: list of he and then converted to int
        return [hex(ord(c)) for c in self.deciphered_text]

    # divide the hex list into 4x4 matrix
    def key_to_matrix(self, key):
        matrix = []
        hex_list = self.key_to_hex(key)
        for i in range(0, len(hex_list), 4):
            matrix.append(hex_list[i:i+4])
        return matrix
    
    def print_plaintext_key(self):
        print("\033[1;32;40m")
        print("Plain Text:")
        print("In ASCII:", self.input_plaintext)
        # print the input plaintext in hex
        print("In HEX:", "".join(i.replace("0x", "") for i in self.plaintext_to_hex()))

        print("\033[1;31;40m")
        print("Key:")
        print("In ASCII:", self.actual_key)
        print("In HEX:", "".join(i.replace("0x", "") for i in self.key_to_hex(self.actual_key)))

    def print_cipher_text(self):
        print("\033[1;31;40m")
        print("Cipher Text:")
        print("In ASCII:", self.cipher_text)
        print("In HEX:", "".join(i.replace("0x", "") for i in self.ciphertext_to_hex()))

    def print_deciphered_text(self):
        print("\033[1;32;40m")
        print("Deciphered Text:")
        self.process_deciphered_text()
        print("In ASCII:", self.deciphered_text)
        print("In HEX:", "".join(i.replace("0x", "") for i in self.deciphered_text_to_hex()))


    def generate_round_keys(self):
        all_round_keys = {}
        new_key = self.key_to_matrix(self.input_key)
        all_round_keys[0] = new_key.copy()
        for i in range(10):
            round_keys = RoundKeysGenerator(new_key, i)
            new_key = round_keys.generate_round_keys()
            all_round_keys[i+1] = new_key.copy()

        self.all_keys = all_round_keys

# =======================================================================================

current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current_dir)
plaintext_file_path = os.path.join(current_dir, "input.txt")
key_file_path = os.path.join(current_dir, "key.txt")
deciphered_text_file_path = os.path.join(current_dir, "output.txt")

# =======================================================================================

if __name__ == "__main__":

    # take input plaintext from a txt file
    with open(plaintext_file_path, "r") as f:
        plaintext = f.read()
    # print("Plaintext:", plaintext)
    f.close()

    with open(key_file_path, "r") as f:
        key = f.read()
    # print("Key:", key)
    f.close()

    user_io = UserIO(key, plaintext)
    user_io.print_plaintext_key()

    # =======================================================================================

    # keep timestamp of key generation here
    key_schedule_start_time = time.time()
    user_io.generate_round_keys()
    key_schedule_end_time = time.time()

    # keep timestamp of encryption here
    encryption_start_time = time.time()        
    encryptor = EncryptionCycle(user_io)

    encryptor.create_state_matrix()
    for i in range(10):
        encryptor.substitute_bytes()
        encryptor.shift_rows()
        if i != 9:
            encryptor.mix_columns()
        encryptor.add_round_key(i)

    cipher_text = ""
    for i in range(len(encryptor.state_matrix)):
    # row major order and save it
        encryptor.state_matrix[i] = encryptor.reorder_column_major_matrix(encryptor.list_to_matrix(encryptor.state_matrix[i]))
    # print(encryptor.state_matrix)
        cipher_text += "".join(encryptor.hex_to_ascii(encryptor.state_matrix[i]))
    
    encryptor.cipher_text = cipher_text
    encryption_end_time = time.time()

    # =======================================================================================

    user_io.set_cipher_text(encryptor.cipher_text)
    user_io.print_cipher_text()

    # =======================================================================================

    # keep timestamp of decryption here
    decryption_start_time = time.time()
    decryptor = DecryptionCycle(user_io)
    decryptor.create_state_matrix()
    for i in range(10):
        decryptor.inverse_shift_rows()
        decryptor.inverse_substitute_bytes()
        decryptor.add_round_key(i)
        if i != 9:
            decryptor.inverse_mix_column()

    deciphered_text = ""
    # column major reorder for state matrix
    for i in range(len(decryptor.state_matrix)):
        decryptor.state_matrix[i] = decryptor.reorder_column_major(decryptor.list_to_matrix(decryptor.state_matrix[i]))
        deciphered_text += "".join(decryptor.hex_to_ascii(decryptor.state_matrix[i]))
    # print(state_matrix)
    decryptor.plaintext = deciphered_text
    decryption_end_time = time.time()

    # =======================================================================================

    user_io.set_deciphered_text(decryptor.plaintext)
    user_io.print_deciphered_text()

    with open(deciphered_text_file_path, "w") as f:
        f.write(user_io.deciphered_text)
    f.close()

    # =======================================================================================
    print("\033[1;33;40m")
    print("Execution Time Details: ")
    print("Key Scheduling: ", key_schedule_end_time - key_schedule_start_time, "seconds")
    print("Encryption time: ", encryption_end_time - encryption_start_time, "seconds")
    print("Decryption time: ", decryption_end_time - decryption_start_time, "seconds")
