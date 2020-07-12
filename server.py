import socket
import pyDH
import re


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

DH_server = pyDH.DiffieHellman(group=14)
DH_generator = DH_server.g
DH_prime = DH_server.p
DH_server_private = DH_server.get_private_key()
DH_server_public = DH_server.gen_public_key()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        print('sending DH initial params to client...')
        data = 'DH_INITIAL_PARAMS ' + 'DH_generator:' + str(DH_generator) + ' DH_prime:' + str(DH_prime)
        conn.sendall(data.encode())

        print('sending server public key to client...')
        data = 'DH_SERVER_PUBLIC_KEY:' + str(DH_server_public)
        conn.sendall(data.encode())

        while True:
            data = conn.recv(1024)
            if not data:
                continue
            data = data.decode()

            if data.startswith('DH_CLIENT_PUBLIC_KEY'):                    # Receiving client public key
                #print('Received -------> "', data, '"')
                DH_client_public = int(re.findall('[0-9]+' , data)[0])
                DH_shared_key = DH_server.gen_shared_key(DH_client_public)
                print("session_key:" , DH_shared_key, '\n')
                print(type(DH_shared_key))
                break
