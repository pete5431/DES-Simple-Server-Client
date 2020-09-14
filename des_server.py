import socket
import base64
from Crypto.Cipher import DES
from server_info import ServerInfo

def start_server(info):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((info.HOST, info.PORT))
        print("Waiting for client to connect...")
        server_socket.listen()
        conn, addr = server_socket.accept()
        with conn:
            print('Client has connected. Address: ', addr)
            while True:
                print("Waiting for client message...")
                incoming_message = conn.recv(1024)
                print('Key:       ', info.KEY.decode('UTF-8'))
                print('Ciphertext:', base64.b64encode(incoming_message).decode('UTF-8'))
                plain_text = decrypt_message(incoming_message, info.KEY)
                print('Plaintext: ', plain_text.decode('UTF-8'))

                outgoing_message = input(str(">>"))
                outgoing_message = pad_message(outgoing_message)
                outgoing_message = encrypt_message(bytes(outgoing_message,'UTF-8'), info.KEY)
                conn.sendall(outgoing_message)


def pad_message(message):
    while len(message) % 8 != 0:
        message = message + ' '
    return message

def encrypt_message(plain_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    cipher_text = cipher.encrypt(plain_text)
    return cipher_text

def decrypt_message(cipher_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text

if __name__ == '__main__':
    info = ServerInfo()
    info.read_key()
    start_server(info)
