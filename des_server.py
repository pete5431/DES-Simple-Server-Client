import socket
import base64
# The DES algorithm used is from the pycryptodome package.
from Crypto.Cipher import DES
from server_info import ServerInfo

"""
The pycryptodome package uses C language code. Therefore in order use strings with pycryptodome functions, bytes objects are used.
"""

def start_server(info):
    """
    The start_server() function takes in an ServerInfo object that contains the HOST, PORT, and KEY.
        -It will establish a connection on the HOST and PORT and listen for connections.
        -Once connected it will listen and send messages in a loop.
        -Ctrl-C to exit or press enter when typing message to exit.
        -The message exchange will be one by one.
        -Outgoing messages are encrypted and incoming messages are decrypted.
        -The client will send the first message while the server waits.
        -Then the server sends its message while the client waits and so on.
        -The key, ciphertext, and plaintext will be printed upon receiving a message from client.
    """
    # Create INET socket. With will automatically close server socket at the end of code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # To avoid the error 'Address already in use'.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind socket to the host and port.
        server_socket.bind((info.HOST, info.PORT))
        print("Waiting for client to connect...")
        # Listen for incoming connections.
        server_socket.listen()
        # Accept connection from client.
        client_connect, client_addr = server_socket.accept()
        # Client socket will automatically close after end of with block.
        with client_connect:
            print('Client has connected. Address: ', client_addr)
            while True:
                print("Waiting for client message...")
                # Will read up to 1024 bytes.
                incoming_message = client_connect.recv(1024)
                # Press enter to close connection.
                if incoming_message == b'':
                    break
                plain_text = decrypt_message(incoming_message, info.KEY)

                print("**********************************************************")
                print('Key:', info.KEY.decode('UTF-8'))
                # The returned plaintext string is in bytes, therefore it must be decoded.
                print('Received Plaintext:', plain_text.decode('UTF-8'))
                # base64 encoding is used to make ciphertext look more legible.
                print('Received Ciphertext:', base64.b64encode(incoming_message).decode('UTF-8'))
                print("**********************************************************")

                outgoing_message = input(str(">>"))
                if outgoing_message == '':
                    break
                # Pad message to be multiple of 8 so that it can be encrypted.
                outgoing_message = pad_message(outgoing_message)
                # Convert string to bytes object, and then encrypt.
                encrypted_outgoing_message = encrypt_message(bytes(outgoing_message,'UTF-8'), info.KEY)
                # Sendall will keeping calling send until the entire buffer is sent.
                client_connect.sendall(encrypted_outgoing_message)

                print("**********************************************************")
                print('Key:', info.KEY.decode('UTF-8'))
                print("Sent Plaintext:", outgoing_message)
                print("Sent Ciphertext:", base64.b64encode(encrypted_outgoing_message).decode('UTF-8'))
                print("**********************************************************")

        print("Connection with client ended.")

def pad_message(message):
    """
    Pads the message so that the number of characters or bytes is a multiple of 8.
        -This is because the key has to be 8 bytes.
        -This function will append spaces onto the string.
    """
    while len(message) % 8 != 0:
        message = message + ' '
    return message

def encrypt_message(plain_text, key):
    """
    Takes the plaintext and key and returns the DES encrypted ciphertext.
        -The DES algorithm is the one given by pycryptodome.
        -ECB mode is used.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    cipher_text = cipher.encrypt(plain_text)
    return cipher_text

def decrypt_message(cipher_text, key):
    """
    Takes the ciphertext and key and returns the DES decrypted plaintext.
        -The DES algorithm is the one given by pycryptodome.
        -ECB mode is used.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text

if __name__ == '__main__':
    info = ServerInfo()
    info.read_key()
    start_server(info)
