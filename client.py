import socket
from message_class import message_encryption

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    client = message_encryption(s)
    while True:
        data = s.recv(1024)
        if not data:
            continue
        data = data.decode()

        if data.startswith('DH_INITIAL_PARAMS'):
            client.Receive_inital_params(data)
            client.send_public_key()

        if data.startswith('DH_PUBLIC_KEY'):
            client.Receive_public_key(data)
            break

    while True:
        message = input('enter your message(enter 0 for close connection): \n')
        if message == '0':
            break
        client.send_message(message)
        while True:
            data = s.recv(1024)
            if not data:
                break
            data = data.decode()
            break

        if data.startswith('CIPHER_TEXT:'):
            print('\nMESSAGE:  ', client.receive_message(data), '\n')
