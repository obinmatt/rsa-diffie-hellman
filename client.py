import socket
import pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256

LENGTH = 2048
PORT = 9000
SERVER = "192.168.50.22"
ADDR = (SERVER, PORT)

def send(message):
  # recv public key from server
  msg = clientSocket.recv(LENGTH).decode()
  # encrypt g^x using public key and send to server
  publicKey = RSA.importKey(msg)
  cipher = PKCS1_OAEP.new(publicKey)
  cipherText = cipher.encrypt(str(A).encode())
  clientSocket.send(cipherText)
  # recv g^y from server
  B = int(clientSocket.recv(LENGTH).decode())
  # client calculates shared key
  skA = pow(B, x, p)
  # Hash shared key
  eskA = sha256(str(skA).encode())
  # send message to server
  key = bytes.fromhex(eskA.hexdigest())
  iv = get_random_bytes(16)
  # encrypt the message using client shared key
  cipher = AES.new(key, AES.MODE_CBC, iv)
  cipherText = cipher.encrypt(Padding.pad(message, 16))
  msg = {'message': cipherText, 'iv': iv}
  pickleMsg = pickle.dumps(msg)
  clientSocket.send(pickleMsg)

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(ADDR)

# Diffie-Hellman
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485
g = 2
x = getrandbits(1024)
A = pow(g, x, p)

send(b'Hello server!')
