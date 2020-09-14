class ServerInfo:

    DEFAULT_HOST = '127.0.0.1'
    DEFAULT_PORT = 54643
    DEFAULT_KEY = b'default_'

    def __init__(self, HOST = DEFAULT_HOST, PORT = DEFAULT_PORT, KEY = DEFAULT_KEY):
        self.HOST = HOST
        self.PORT = PORT
        self.KEY = KEY

    def read_key(self):
        key_file = open('key_file.txt', 'r')
        self.KEY = bytes(key_file.read(8), 'utf-8')
        key_file.close()
