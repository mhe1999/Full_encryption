import socket
from message_class import message_encryption

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        server = message_encryption(conn)
        server.send_initial_params()
        server.send_public_key()
        while True:
            data = conn.recv(1024)
            if not data:
                continue
            data = data.decode()

            if data.startswith('DH_PUBLIC_KEY'):
                server.Receive_public_key(data)
                break

        while True:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                data = data.decode()
                break

            if data.startswith('CIPHER_TEXT:'):
                print('\nMESSAGE:  ', server.receive_message(data), '\n')

            message = input('enter your message(enter 0 for close connection): \n')
            if message == '0':
                break
            server.send_message(message)
