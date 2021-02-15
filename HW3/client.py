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
client.connect((address, 8011))

# encrypts message with AES and sends to the server 
def encryptAES(message):
	# get shared key from keyfile
	# key = ""
	key_file = open("key_file.bin", "rb")
	key = key_file.read(16)	
	print("\nFound shared key: " + str(key))
#	print(key)
#	print("Key file type: "+str(type(key)))	
	
	#generate and send ciphertext and nonce
	cipher = AES.new(key, AES.MODE_EAX)
#	cipher = AES.new(b'\x80\xbe\xd2;\x83ZJ2\x14!\xdb\xef\xf0\xcfV\x8d'.encode("utf-8"), AES.MODE_EAX)
#	cipher = AES.new('0101010101010101'.encode("utf-8"), AES.MODE_EAX)		

	nonce = cipher.nonce
	ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))

	print("Sending nonce to server: " + str(nonce))
#	print("nonce:")
#	print(nonce)
	print("Sending ciphertext to server: " + str(ciphertext))
	print("Sending tag to server: " + str(tag))
	
	#debug
#	out = "1#" + str(nonce) + "#" + str(ciphertext) + "#" + str(tag)
	#out = "1#"	
	#print("Sending message \"" + out + "\"")
	#return(out)

#	send("1#" + str(nonce) + "#" + str(ciphertext) + "#" + str(tag))
#	send("1#" + nonce + "#" + ciphertext + "#" + tag)	
	send("1#" + nonce.decode("latin-1") + "#" + ciphertext.decode("latin-1") + "#" + tag.decode("latin-1"))	

# encrypts message with RSA and sends to the server	
def encryptRSA(message):
	send("2#aaaa")

def main():
	#send connection request, wait, then print response
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

def send(request):
	print("SENDING REQUEST:")
	print(request)
#	print("SENDING BYTES(REQUEST):")
#	print(bytes(request, 'utf-8'))
	client.send(bytes(request, 'utf-8'))
	time.sleep(1)
	recieve = str(client.recv(4096))
#	print("Received:")
	print("\n"+recieve.replace("b'","").replace("'","").replace('b"','').replace('"','')+"\n")

main()
