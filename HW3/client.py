# JOHN OSTERMUELLER
# 010887505
# Cryptography HW3

# This program (client.py) is "Alice", who encrypts messages and sends them to "Bob" (server.py).
# First, enter an 18-byte message, then select the encryption scheme.

import socket
import time

# PyCryptodome
from Cryptodome.Cipher import AES
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html?highlight=aes
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html?highlight=rsa

# declare+connect socket
address='127.0.0.1'
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((address, 8012))

# Encrypts message with AES and sends nonce, ciphertext, and tag to the server 
def encryptAES(message):
	# Get shared key from keyfile
	key_file = open("AES_key_file.bin", "rb")
	key = key_file.read(16)	
	print("\nFound shared key: " + str(key))
#	print("Key file type: "+str(type(key)))	
	
	# Get cipher from key, then use cipher to generate nonce, ciphertext, and tag
	cipher = AES.new(key, AES.MODE_EAX)
	nonce = cipher.nonce
	ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
	print("Sending nonce to server: " + str(nonce))
	print("Sending ciphertext to server: " + str(ciphertext))
	print("Sending tag to server: " + str(tag))

	# Send nonce, ciphertext, and tag to server
	send("1#" + nonce.decode("latin-1") + "#" + ciphertext.decode("latin-1") + "#" + tag.decode("latin-1"))	
	
	# Note:
	# Nonce, ciphertext, and tag are decoded as latin-1 strings individually, then
	# the entire message is encoded with utf-8 before being sent. The messages
	# are then decoded to utf-8 strings by the server and the individual vars are
	# re-encoded using latin-1.

# Encrypts message with RSA and sends to the server	
def encryptRSA(message):
	send("2#aaaa")

def main():
	# Send connection request, wait, then print response
	client.send(bytes("0#"+address, 'utf-8'))
	time.sleep(1)
	print("\n"+str(client.recv(4097)).replace("b'","").replace("'","")+"\n")

	menu()

def menu():
	while True:
		ciphertext = ""
		inp = input("Select an encryption scheme:\n1 - 128-bit AES\n2 - 2048-bit RSA\n\n")
		if(inp=="1"):
			message = input("Please enter an 18-byte message to send to Bob:\n")
			encryptAES(message);
		elif(inp=="2"):
			message = input("Please enter an 18-byte message to send to Bob:\n")
			encryptRSA(message)
		elif(inp=="3"):
			send("3#")
			client.close()
			exit()
		else:
			print("Please enter valid input, or enter 3 to exit e.g. \"1\", \"2\", \"3\", ...)")	

# Send a request to the server
# request = str = message to be sent
def send(request):
	print("SENDING REQUEST:")
	print(request)
	client.send(bytes(request, 'utf-8'))
	time.sleep(1)
	recieve = str(client.recv(4096))
	print("\n"+recieve.replace("b'","").replace("'","").replace('b"','').replace('"','')+"\n")

main()
