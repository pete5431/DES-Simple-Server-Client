import socket
import base64
from Crypto.Cipher import DES
from server_info import ServerInfo

def connect_to_server(info):
    """
    Connects to the server using the HOST and PORT from the ServerInfo object.
        -Will be allowed to send the first message.
        -Ctrl-C to exit or press enter will typing message to exit.
    """
    # With will automatically close the client_socket at the end of the code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the server using the server host and port.
        client_socket.connect((info.HOST, info.PORT))
        print("Press Enter without typing anything else to close connection.")
        while True:
            outgoing_message = input(str(">>"))
            # Press enter to close connection.
            if outgoing_message == '':
                break
            # Pad message so that it can be encrypted.
            outgoing_message = pad_message(outgoing_message)
            # Convert string to bytes object, and then encrypt.
            encrypted_outgoing_message = encrypt_message(bytes(outgoing_message,'UTF-8'), info.KEY)
            # sendall will keeping calling send until the entire buffer is sent.
            client_socket.sendall(encrypted_outgoing_message)

            print("**********************************************************")
            print('Key:', info.KEY.decode('UTF-8'))
            print("Sent Plaintext:", outgoing_message)
            print("Sent Ciphertext:", base64.b64encode(encrypted_outgoing_message).decode('UTF-8'))
            print("**********************************************************")

            print("Waiting for server message...")
            # Will read up to 1024 bytes.
            incoming_message = client_socket.recv(1024)
            if incoming_message == b'':
                break
            plain_text = decrypt_message(incoming_message, info.KEY)

            print("**********************************************************")
            print('Key:', info.KEY.decode('UTF-8'))
            print('Received Plaintext:', plain_text.decode('UTF-8'))
            print('Received Ciphertext:', base64.b64encode(incoming_message).decode('UTF-8'))
            print("**********************************************************")

    print("Connection has been closed.")

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
    connect_to_server(info)
