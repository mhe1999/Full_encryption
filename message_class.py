import pyDH
import re
from Crypto.Cipher import AES
from hashlib import sha256
import base64


class message_encryption:
    def __init__(self, conn):
        self.DH = pyDH.DiffieHellman(group=14)
        self.DH_generator = self.DH.g
        self.DH_prime = self.DH.p
        self.DH_private = self.DH.get_private_key()
        self.DH_public = self.DH.gen_public_key()
        self.conn = conn

    def send_initial_params(self):
        print('sending DH initial params to client...')
        data = 'DH_INITIAL_PARAMS ' + 'DH_generator:' + str(self.DH_generator) + ' DH_prime:' + str(self.DH_prime)
        self.conn.sendall(data.encode())

    def send_public_key(self):
        print('sending public key...')
        data = 'DH_PUBLIC_KEY:' + str(self.DH_public)
        self.conn.sendall(data.encode())

    def calculate_shared_key(self):
        print('calculate shared_key...')
        self.DH_shared_key = self.DH.gen_shared_key(self.DH_other_side_public)
        #print("session_key:" , self.DH_shared_key, '\n')

    def Receive_inital_params(self, data):
        print('generator and prime has been Received...')
        self.DH_prime = int(re.findall('DH_prime:([0-9]+)', data)[0])
        self.DH_generator = int(re.findall('DH_generator:([0-9]+)', data)[0])
        self.DH_private = self.DH.get_private_key()
        self.DH_public = self.DH.gen_public_key()

    def Receive_public_key(self, data):
        print('other party\'s public key has been Received...')
        self.DH_other_side_public = int(re.findall('[0-9]+' , data)[0])
        self.calculate_shared_key()

    def encryption(self, plaintext):
        print('encrypting data...')
        cipher = AES.new(int(self.DH_shared_key, 16).to_bytes(32, byteorder = 'big'),AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode()) # encryte data
        return ciphertext, nonce

    def decryption(self, message_bytes, nonce):
        print('decrypting data...')
        cipher = AES.new(int(self.DH_shared_key, 16).to_bytes(32, byteorder = 'big'), AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(message_bytes)               # decrype message with session key and nonce
        plaintext = plaintext.decode()
        return plaintext

    def calculate_hash(self, message):
        return sha256(message.encode())

    def base64_encode(self, message_bytes):
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def base64_decode(self, base64_message):
        base64_bytes = base64_message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes

    def send_message(self, message):
        print('sending message...')
        data = 'message:' + message + ',hash:' + self.calculate_hash(message).hexdigest()
        ciphertext, nonce = self.encryption(data)
        base64_cyphertext = self.base64_encode(ciphertext)
        base64_nonce = self.base64_encode(nonce)
        encryted_data = 'CIPHER_TEXT:' + str(base64_cyphertext) + ', NONCE:' + str(base64_nonce)
        self.conn.sendall(encryted_data.encode())
        print('message has been send')

    def check_integrity(self, message, hash):
        if hash == self.calculate_hash(message).hexdigest():
            return True

    def receive_message(self, data):
        print('message Received...')
        #print('Received -------> "', data, '"')
        base64_cyphertext = re.findall('CIPHER_TEXT:(.+),', data)[0]
        base64_nonce = re.findall('NONCE:(.+)', data)[0]
        ciphertext = self.base64_decode(base64_cyphertext)
        nonce = self.base64_decode(base64_nonce)
        message_and_hash = self.decryption(ciphertext, nonce)
        message = re.findall('message:(.+),', message_and_hash)[0]
        hash = re.findall(',hash:(.+)', message_and_hash)[0]

        if not self.check_integrity(message, hash):
            return 'message integrity is compromised'
        else:
            return message
        #print('the dectypted message of Received message: ', plaintext)
