import socket
import base64
from security_info import SecurityInfo

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
            # Calculate the hmac of the outgoing message.
            outgoing_hmac = info.calculate_hmac(outgoing_message)
            # Concatenate the hmac onto the message and pad it, and encrypt using DES.
            encrypted_outgoing_message = info.encrypt_message(pad_message(outgoing_message + outgoing_hmac))
            # sendall will keeping calling send until the entire buffer is sent.
            client_socket.sendall(encrypted_outgoing_message)

            print("**********************************************************")
            print('DES Key:', info.DESKEY.decode('UTF-8'))
            print('HMAC Key:', info.HMACKEY.decode('UTF-8'))
            print("Sent Plaintext:", outgoing_message)
            print("Calculated HMAC:", outgoing_hmac)
            print("Sent Ciphertext:", base64.b64encode(encrypted_outgoing_message).decode('UTF-8'))
            print("**********************************************************")

            print("Waiting for server message...")
            # Will read up to 1024 bytes.
            incoming_message = client_socket.recv(1024)
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
            print('Received Plaintext:', split_message[0])
            print('Received Ciphertext:', base64.b64encode(incoming_message).decode('UTF-8'))
            print('Calculated HMAC:', calculated_hmac)
            print('Received HMAC:', split_message[1])
            if hmac_match:
                print('HMAC Verified.')
            else:
                print('HMAC Not Verified.')
            print("**********************************************************")

    print("Connection has been closed.")

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
    # Connect to server.
    connect_to_server(info)
