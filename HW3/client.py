# JOHN OSTERMUELLER
# 010887505
# Cryptography HW3

# This program (client.py) is "Alice", who encrypts messages and sends them to "Bob" (server.py).
# First, enter an 18-byte message, then select the encryption scheme.
# PyCryptodome:
# pip install pycryptodomex
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html?highlight=aes
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html?highlight=rsa
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
import socket
import time
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA

# declare+connect socket
address='127.0.0.1'
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((address, 8000))

# Encrypts message with AES_EAX and sends nonce, ciphertext, and tag to the server 
def encryptAES_EAX(message):
	# Get shared key from keyfile
	key_file = open("AES_key_file.bin", "rb")
	key = key_file.read(16)	
	print("\nFound shared key: " + str(key))
#	print("Key file type: "+str(type(key)))	
	
	# Get cipher from key, then use cipher to generate nonce, ciphertext, and tag
	cipher = AES.new(key, AES.MODE_EAX)
	nonce = cipher.nonce
	ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
	ciphertext, tag = cipher.encrypt_and_digest(pad(message.encode("utf-8"), AES.block_size))
	print("Sending nonce to server: " + str(nonce))
	print("Sending ciphertext to server: " + str(ciphertext))
	print("Sending tag to server: " + str(tag))

	# Send nonce, ciphertext, and tag to server
	send("1#####" + nonce.decode("latin-1") + "#####" + ciphertext.decode("latin-1") + "#####" + tag.decode("latin-1"))	
	
	# Note:
	# Nonce, ciphertext, and tag are decoded as latin-1 strings individually, then
	# the entire message is encoded with utf-8 before being sent. The messages
	# are then decoded to utf-8 strings by the server and the individual vars are
	# re-encoded using latin-1.

# Encrypts message with AES_CBC and sends nonce, ciphertext, and tag to the server 
def encryptAES_CBC(message):
	# Get shared key from keyfile
	key_file = open("AES_key_file.bin", "rb")
	key = key_file.read(16)	
	print("\nFound shared key: " + str(key))
#	print("Key file type: "+str(type(key)))	
	
	# Get cipher from key, then use cipher to generate nonce, ciphertext, and tag
	cipher = AES.new(key, AES.MODE_CBC)
	iv = cipher.iv
	ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
	print("Sending IV to server: " + str(iv))
	print("Sending ciphertext to server: " + str(ciphertext))

	# Send iv and ciphertext to server
	send("2#####" + iv.decode("latin-1") + "#####" + ciphertext.decode("latin-1"))	
	
	# Note:
	# Nonce, ciphertext, and tag are decoded as latin-1 strings individually, then
	# the entire message is encoded with utf-8 before being sent. The messages
	# are then decoded to utf-8 strings by the server and the individual vars are
	# re-encoded using latin-1.

# Encrypts message with RSA and sends to the server	
def encryptRSA(message):
	public_key = RSA.import_key(open("RSA_key_file.pem").read())
	print("\nFound public RSA key: " + str(public_key))	
	cipher = PKCS1_OAEP.new(public_key)
	ciphertext = cipher.encrypt(message.encode("utf-8"))
	send("3#####" + ciphertext.decode("latin-1"))

def main():
	# Send connection request, wait, then print response
	client.send(bytes("0#####"+address, 'utf-8'))
	time.sleep(1)
	print("\n"+str(client.recv(4097)).replace("b'","").replace("'","")+"\n")

	menu()

def menu():
	while True:
		ciphertext = ""
		inp = input("Select an encryption scheme:\n1 - 128-bit AES_EAX\n2 - 128-bit AES_CBC\n3 - 2048-bit RSA\n\n")
		if(inp=="1"):
			message = input("Please enter an 18-byte message to send to Bob:\n")
			encryptAES_EAX(message);
		elif(inp=="2"):
			message = input("Please enter an 18-byte message to send to Bob:\n")
			encryptAES_CBC(message)
		elif(inp=="3"):
			message = input("Please enter an 18-byte message to send to Bob:\n")
			encryptRSA(message)
		elif(inp=="4"):
			send("4#")
			client.close()
			exit()
		else:
			print("Please enter valid input, or enter 3 to exit e.g. \"1\", \"2\", \"3\", ...)")	

# Send a request to the server
# request = str = message to be sent
def send(request):
	print("SENDING REQUEST:")
	print(shorten(str(request)))
	client.send(bytes(request, 'utf-8'))
	time.sleep(1)
	recieve = str(client.recv(4096))
	print("\n"+recieve.replace("b'","").replace("'","").replace('b"','').replace('"','')+"\n")

# Shortens a string if len>20
def shorten(string):
	if len(string) > 20: return string[:40] + "..."
	else: return string

main()
