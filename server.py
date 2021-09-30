import socket
import threading
import pickle

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256

LENGTH = 2048
PORT = 9000
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

def generateRSAkeys():
  key = RSA.generate(2048)
  pem = key.export_key(format='PEM', passphrase='dees')
  f = open('private.pem', 'wb')
  f.write(pem)
  f.close()
  pub = key.publickey()
  pub_pem = pub.export_key(format='PEM')
  f = open('public.pem', 'wb')
  f.write(pub_pem)
  f.close()

def handleClient(connection, addr):
  print(f"New connection - {addr}")
  connected = True
  while connected:
    # send public key to client
    publicKey = open('public.pem').read()
    connection.send(publicKey.encode())
    # recv RSA(g^x) from client
    encyptedA = connection.recv(LENGTH)
    # decrypt A
    privateKey = RSA.importKey(open('private.pem').read(), passphrase='dees')
    cipher = PKCS1_OAEP.new(privateKey)
    plainText = cipher.decrypt(encyptedA)
    decryptedA = int(plainText.decode())
    # send g^y to client
    connection.send(str(B).encode())
    # server calculates shared key
    skB = pow(decryptedA, y, p)
    # Hash shared key
    eskB = sha256(str(skB).encode())
    # recv message from client
    msg = pickle.loads(connection.recv(LENGTH))
    cipherText = msg['message']
    iv = msg['iv']
    # decrypt msg
    key = bytes.fromhex(eskB.hexdigest())
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plainText = cipher.decrypt(cipherText)
    print(f'message: {Padding.unpad(plainText, 16)}')
    connected = False
  connection.close()
  print(f"Connection closed - {addr}")

# Diffie-Hellman
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485
g = 2
y = getrandbits(1024)
B = pow(g, y, p)

# create RSA keys
generateRSAkeys()

# init socket
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(ADDR)
serverSocket.listen()
print(f"Server is listening on {SERVER}")

while True:
  connection, addr = serverSocket.accept()
  thread = threading.Thread(target=handleClient, args=(connection, addr))
  thread.start()
  print(f"Number of connections: {threading.activeCount() - 1}")
