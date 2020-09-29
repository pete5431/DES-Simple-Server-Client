# The DES algorithm used is from the pycryptodome package.
from Crypto.Cipher import DES
# The HMAC algorithm used is from the pycryptodome package. Default is HMAC-MD5.
from Crypto.Hash import HMAC

"""
The pycryptodome package uses C language code. Therefore in order use strings with pycryptodome functions, bytes objects are used.
"""

class SecurityInfo:

    """
    Class that holds the infomration for ports, and host. Also contains encryption/decryption functions and keys.
    """

    DEFAULT_HOST = '127.0.0.1'
    DEFAULT_PORT = 54643
    DEFAULT_KEY = b'default_';

    def __init__(self, HOST = DEFAULT_HOST, PORT = DEFAULT_PORT, KEY = DEFAULT_KEY):
        """
        Constructor for ServerInfo.
            -Uses default values if none are provided.
        """
        self.HOST = HOST
        self.PORT = PORT
        self.DESKEY = KEY
        self.HMACKEY = KEY
        # DES object from pycryptodome used for DES encryption.
        self.DES = DES.new(self.DESKEY, DES.MODE_ECB)

    def read_des_key(self):
        """
        Reads the des key from des_key.txt
            -Will read the first 8 bytes because key is 8-bytes.
        """
        key_file = open('des_key.txt', 'r')
        self.DESKEY = bytes(key_file.read(8), 'utf-8')
        self.DES = DES.new(self.DESKEY, DES.MODE_ECB)
        key_file.close()

    def read_hmac_key(self):
        """
        Reads the hmac key from hmac_key.txt
        """
        key_file = open('hmac_key.txt', 'r')
        self.HMACKEY = bytes(key_file.read().rstrip(), 'utf-8')
        key_file.close()

    def encrypt_message(self, plain_text):
        """
        Takes the plaintext and key and returns the DES encrypted ciphertext.
            -The DES algorithm is the one given by pycryptodome.
            -ECB mode is used.
            -Encodes plaintext to bytes because of pycryptodome using C.
        """
        cipher_text = self.DES.encrypt(bytes(plain_text,'UTF-8'))
        return cipher_text

    def decrypt_message(self, cipher_text):
        """
        Takes the ciphertext and key and returns the DES decrypted plaintext.
            -The DES algorithm is the one given by pycryptodome.
            -ECB mode is used.
            -Encodes plaintext to bytes because of pycryptodome using C.
        """
        plain_text = self.DES.decrypt(cipher_text)
        return plain_text

    def calculate_hmac(self, plaintext):
        """
        Calculates the hmac of the given plaintext.
            -Uses HMAC-MD5.
            -Update remembers previous messages.
            -Therefore a new HMAC object needs to be created everytime.
            -Encodes plaintext to bytes because of pycryptodome using C.
        """
        self.HMAC = HMAC.new(self.HMACKEY)
        self.HMAC.update(bytes(plaintext, 'UTF-8'))
        return self.HMAC.hexdigest()

    def split_hmac(self, plaintext):
        """
        Splits the hmac from the message.
            -Returns a list.
            -Index 0 contains the plaintext message.
            -Index 1 contains the attached hmac.
        """
        #Since HMAC-MD5 is used, the length of the digest is always 32 hexadecimal digits.
        split_string = [plaintext[0:len(plaintext) - 32], plaintext[-32:]]
        return split_string

    def verify_hmac(self, received_hmac, calculated_hmac):
        """
        Compares the received hmac and calculated hmac.
            -Returns true if they match. Else false.
        """
        if received_hmac == calculated_hmac:
            return True
        else:
            return False
