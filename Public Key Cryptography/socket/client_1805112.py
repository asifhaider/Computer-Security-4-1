import socket
import sys, os
sys.path.append(os.path.join(os.path.dirname(sys.path[0]), 'aes_dh'))
from aes_1805112 import *
from diffie_hellman_1805112 import *

class Client:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = 12345
        self.socket.connect(('localhost', self.port))

    def create_decipher(self, ciphertext):
        key = str(self.secret)
        user_input = UserIO(key, None)
        user_input.generate_round_keys()
        user_input.set_cipher_text(ciphertext)

        decryptor = DecryptionCycle(user_input)
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

        user_input.set_deciphered_text(deciphered_text)        # print(state_matrix)

        user_input.process_deciphered_text()

        # return deciphered text with trimming all the padding constants from the last
        return user_input.deciphered_text.rstrip(user_input.padding_constant)

    def run(self):
        data = None
        while True:
            if data == '':
                 break
            else:          
                print("\033[1;31;40m")
                data = self.socket.recv(1024).decode('utf-8')
                print(data)
                if data == 'Alice: Sending modulus, generator and public key separated by new line':
                    # extract modulus, generator, and public key
                    data = self.socket.recv(1024).decode('utf-8')
                    data = data.split('\n')
                    p = int(data[0])
                    g = int(data[1])
                    A = int(data[2])

                    print("\033[1;33;40m")
                    print('Bob: Received modulus, generator and public key')

                    # generate bob's public key
                    dh = DiffieHellman()
                    dh.set_modulus(p)
                    b = dh.generate_prime(64)
                    B = dh.compute_key(g, b)

                    # send bob's public key
                    self.send_message(str(B))

                    print('Bob: Sent my public key')

                    # compute shared secret
                    s2 = dh.compute_key(A, b)
                    print('Bob: Shared secret: ' + str(s2))

                    self.secret = s2
                    print("\033[1;34;40m")
       
                    # receive ready message
                    data = self.socket.recv(1024).decode('utf-8')
                    print(data)

                    # if data contains 'ready', send my ready message
                    if 'ready' in data.lower():
                        self.send_message('Bob: Ready to receive encrypted message')
                        print("\033[1;32;40m")

                        # receive encrypted message
                        ciphertext = self.socket.recv(1024).decode('utf-8')
                        print('Bob: Received encrypted message:\n', ciphertext)

                        # decrypt message
                        plaintext = self.create_decipher(ciphertext)

                        print('Bob: Decrypted message:\n', plaintext)
                    
                        # write to file
                        with open(deciphered_text_file_path, 'w') as f:
                            f.write(plaintext)
                        f.close()

                        # successfully close connection
                        self.send_message('Bob: Closing connection')
                        break
            
    
    def send_message(self, message):
        self.socket.send(message.encode('utf-8'))

    def get_server(self):
        return self.server

if __name__ == '__main__':
    current_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(current_dir)
    deciphered_text_file_path = os.path.join(current_dir, "output.txt")
    bob = Client()
    bob.run()