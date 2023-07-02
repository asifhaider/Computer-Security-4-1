import socket
import sys, os
sys.path.append(os.path.join(os.path.dirname(sys.path[0]), 'aes_dh'))
from aes_1805112 import *
from diffie_hellman_1805112 import *

class Server:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = 12345
        self.socket.bind(('', self.port))
        self.socket.listen(5)

    def create_cipher(self):
        print("\033[1;32;40m")
        # plaintext = input('Enter plaintext: ')
        with open(plaintext_file_path, "r") as f:
            plaintext = f.read()
        f.close()
        self.plaintext = plaintext
        key = str(self.secret)

        user_input = UserIO(key, plaintext)
        user_input.generate_round_keys()
        encryptor = EncryptionCycle(user_input)
        encryptor.create_state_matrix()
        for i in range(10):
            encryptor.substitute_bytes()
            encryptor.shift_rows()
            if i != 9:
                encryptor.mix_columns()
            encryptor.add_round_key(i)
        # row major order and save it
        cipher_text = ""
        for i in range(len(encryptor.state_matrix)):
        # row major order and save it
            encryptor.state_matrix[i] = encryptor.reorder_column_major_matrix(encryptor.list_to_matrix(encryptor.state_matrix[i]))
        # print(encryptor.state_matrix)
            cipher_text += "".join(encryptor.hex_to_ascii(encryptor.state_matrix[i]))
    
        encryptor.cipher_text = cipher_text
        return encryptor.cipher_text

    def run(self):
        while True:
            print("\033[1;31;40m")
            self.client, addr = self.socket.accept()
            print('Alice: Got connection from', addr)
            self.client.send('Alice: Thanks for connecting!'.encode('utf-8'))
            print("\033[1;33;40m")
            self.client.send('Alice: Sending modulus, generator and public key separated by new line'.encode('utf-8'))

            # send bob the modulus, generator, and public key
            dh = DiffieHellman()
            p = dh.generate_prime(128)
            dh.set_modulus(p)
            g = dh.find_generator(2, p-2)
            a = dh.generate_prime(64)
            A = dh.compute_key(g, a)
            self.send_message(self.client, str(p) + "\n" + str(g) + "\n" + str(A))

            print('Alice: Sent my modulus, generator and public key')

            # receive bob's public key
            B = self.client.recv(1024).decode('utf-8')
            B = int(B)

            print('Alice: Received Bob\'s public key')

            # compute shared secret
            s1 = dh.compute_key(B, a)
            print('Alice: Shared secret: ' + str(s1))

            self.secret = s1
            print("\033[1;34;40m")

            # send ready message
            self.send_message(self.client, 'Alice: Ready to send encrypted message')

            # receive ready message
            data = self.client.recv(1024).decode('utf-8')
            print(data)

            # if data contains 'ready', send aes encrypted ciphertext
            if 'ready' in data.lower():
                # print plaintext
                ciphertext = self.create_cipher()
                print('Alice: Plaintext:\n', self.plaintext)
                self.send_message(self.client, ciphertext)

                print('Alice: Sent encrypted message:\n', ciphertext)

                print("\033[1;34;40m")

                # receive closing message
                data = self.client.recv(1024).decode('utf-8')
                print(data)

                # if data contains 'close', close connection
                if 'closing' in data.lower():
                    self.client.close()
                    print('Alice: Connection closed')
                    break

            
    def send_message(self, client, message):
        client.send(message.encode('utf-8'))            

    def get_client(self):
        return self.client


if __name__ == '__main__':
    current_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(current_dir)
    plaintext_file_path = os.path.join(current_dir, "input.txt")
    alice = Server()
    alice.run()