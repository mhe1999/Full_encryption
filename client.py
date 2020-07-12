import socket
import pyDH
import re


HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

DH_client = pyDH.DiffieHellman(group=14)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        data = s.recv(1024)
        if not data:
            continue
        data = data.decode()
        print('Received -------> "', data, '"')

        if data.startswith('DH_INITIAL_PARAMS'):
            prime = int(re.findall('DH_prime:([0-9]+)', data)[0])
            generator = int(re.findall('DH_generator:([0-9]+)', data)[0])
            DH_client.p = prime
            DH_client.g = generator
            DH_client_private = DH_client.get_private_key()
            DH_client_public = DH_client.gen_public_key()
            print("\nsending the client's public key to server...\n") # send client's public key without encryption
            data = 'DH_CLIENT_PUBLIC_KEY:' + str(DH_client_public)
            s.sendall(data.encode())

        if data.startswith('DH_SERVER_PUBLIC_KEY'):                # Receiving servers's public key
            DH_server_public = int(re.findall('[0-9]+' , data)[0])
            DH_shared_key = DH_client.gen_shared_key(DH_server_public)
            #print('client public key:' , hex(client_public))
            #print('client private key:', hex(cilent_private))
            #print('server public key:' , hex(server_public))
            #session_key = (server_public ^ cilent_private) % prime  # calculate session key base on server's public key and client's private key
            print("session_key:" , DH_shared_key, '\n')
            print(type(DH_shared_key))
            break
