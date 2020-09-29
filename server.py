import socket
import base64
from security_info import SecurityInfo

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

        New Addition:
        -Now uses HMAC-MD5.
        -Digest concatenated to message and encrypted using DES.
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
                plain_text = info.decrypt_message(incoming_message)
                # Unpad the plaintext and split to obtain hmac and message.
                split_message = info.split_hmac(unpad_message(plain_text))
                # Calculate the hmac of the message.
                calculated_hmac = info.calculate_hmac(split_message[0])
                # Verify the two hmacs.
                hmac_match = info.verify_hmac(split_message[1], calculated_hmac)

                print("**********************************************************")
                print('HMAC Key:', info.HMACKEY.decode('UTF-8'))
                # The returned plaintext string is in bytes, therefore it must be decoded.
                print('Received Plaintext:', split_message[0])
                # base64 encoding is used to make ciphertext look more legible.
                print('Received Ciphertext:', base64.b64encode(incoming_message).decode('UTF-8'))
                print('Calculated HMAC:', calculated_hmac)
                print('Received HMAC:', split_message[1])
                # If hmacs are the same print verified, or not verified otherwise.
                if hmac_match:
                    print('HMAC Verified.')
                else:
                    print('HMAC Not Verified.')
                print("**********************************************************")

                outgoing_message = input(str(">>"))
                if outgoing_message == '':
                    break
                # Calculate the hmac of the outgoing message.
                outgoing_hmac = info.calculate_hmac(outgoing_message)
                # Concatenate the hmac onto the message and pad it, and encrypt using DES.
                encrypted_outgoing_message = info.encrypt_message(pad_message(outgoing_message + outgoing_hmac))
                # Sendall will keeping calling send until the entire buffer is sent.
                client_connect.sendall(encrypted_outgoing_message)

                print("**********************************************************")
                print('DES Key:', info.DESKEY.decode('UTF-8'))
                print('HMAC Key:', info.HMACKEY.decode('UTF-8'))
                print("Sent Plaintext:", outgoing_message)
                print("Calculated HMAC:", outgoing_hmac)
                print("Sent Ciphertext:", base64.b64encode(encrypted_outgoing_message).decode('UTF-8'))
                print("**********************************************************")

        print("Connection with client ended.")

def pad_message(message):
    """
    Pads the message so that the number of characters or bytes is a multiple of 8.
        -This is because the key has to be 8 bytes.
        -Uses PKCS5 padding.
        -Pads with byte that are the same value as the number of padding bytes to be added.
    """
    # Calculates the number of padding bytes required.
    pad_value = (8 - len(message) % 8)
    # If 8, then the message is ok as is.
    if pad_value != 8:
        # Convert the padding value to ASCII and multiply by itself and append to message.
        message += (pad_value * chr(pad_value))
    return message

def unpad_message(message):
    """
    Unpads the message so that original message is obtained.
        -Checks the last value in the message, which will be the padding value if padding was added.
        -Then checks to make sure the count of the padding value matches the padding value.
    """
    # Received messages will be bytes objects. Need to decode for string.
    message = message.decode('UTF-8')
    # If length of message is zero. Return message.
    if(len(message) == 0):
        return message
    # Uses ord() to convert last value to int value.
    pad_value = ord(message[-1])
    # If the padded value is not 1-7, then no padding was added.
    if pad_value not in range(1,8):
        return message
    i = -2
    counter = 1
    # Loop to count the number of padding values.
    while message[i] == message[-1]:
        counter+=1;
        i-=1;
    # If the number of padding values equals the padding value then padding was used.
    if counter == pad_value:
        # Return the message without the padding.
        return message[0:-pad_value]
    else:
        return message

if __name__ == '__main__':
    # Creates the ServerInfo object. A host, port, and key can be passed otherwise it will use the defaults.
    info = SecurityInfo()
    # Read the key from key_file.txt, otherwise it uses the default key.
    info.read_des_key()
    # Read the key from hmac_file.txt, otherwise it uses the default key.
    info.read_hmac_key()
    # Start the server with using the info.
    start_server(info)
