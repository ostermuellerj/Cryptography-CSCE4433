#JOHN OSTERMUELLER
#010887505
#Cryptography HW3

# This program (server.py) is "Bob", who decryptes messages and returns them to "Alice" (client.py).

# PyCryptodome:
# pip install pycryptodomex
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html?highlight=aes
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html?highlight=rsa

import socket
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA

portNum = 8000
serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind(('127.0.0.1', portNum))
serv.listen(5)

# Generate AES key file (Alice/Client and Bob/Server can both access, we assume it is secure)
key_file = open("AES_key_file.bin", "wb")
key = get_random_bytes(16)
print("\nAES shared key generated: ")
print(key)
key_file.write(key) 
key_file.close()

# Generate RSA public key and place in key file. 
RSA_key = RSA.generate(2048)
print("\nRSA public key generated (hidden).")
public_key = RSA_key.export_key()
RSA_key_file = open("RSA_key_file.pem", "wb")
RSA_key_file.write(public_key)
RSA_key_file.close()

print("\nWaiting for connection on 0.0.0.0:" + str(portNum)+" ...")

# Decrypt an AES_EAX-encrypted message given the nonce, ciphertext, and tag
def encryptAES_EAX(nonce, ciphertext, tag):
	print("RECIEVED FROM CLIENT...")
	print("Nonce: " + shorten(str(nonce)))
	print("Ciphertext: " + shorten(str(ciphertext)))
	print("Tag: " + shorten(str(tag)) + "\n")		
	
	try:
		cipher = AES.new(key, AES.MODE_EAX, nonce=nonce.encode("latin-1"))		
	except Exception as e: 
		print(e)
	
	try:
#		out = cipher.decrypt(ciphertext.encode("latin-1"))
		out = cipher.decrypt_and_verify(ciphertext.encode("latin-1"), tag.encode("latin-1"))
	except Exception as e: 
		print(e)
		print('cannot decrypt')
		
	try:
		return out
	except Exception as e: 
		print(e)
		print('cannot return decryption')

# Decrypt an AES_CBC-encrypted message given the iv and ciphertext
def encryptAES_CBC(iv, ciphertext):
	print("RECIEVED FROM CLIENT...")
	print("IV: " + shorten(str(iv)))
	print("Ciphertext: " + shorten(str(ciphertext)))	
	
	try:
		cipher = AES.new(key, AES.MODE_CBC, iv.encode("latin-1"))		
	except Exception as e: 
		print(e)
	
	try:
		out = unpad(cipher.decrypt(ciphertext.encode("latin-1")), AES.block_size)
	except Exception as e: 
		print(e)
		print('cannot decrypt')
		
	try:
		return out
	except Exception as e: 
		print(e)
		print('cannot return decryption')
		

def decryptRSA(ciphertext):
	print("RECIEVED FROM CLIENT...")
	print("Ciphertext: " + shorten(str(ciphertext)) + "\n")	
	
	try:
		cipher = PKCS1_OAEP.new(RSA.import_key(open("RSA_key_file.pem").read()))		
	except Exception as e: 
		print(e)
		print("cannot make rsa cipher")
	
	try:
		out = cipher.decrypt(ciphertext.encode("latin-1"))
	except Exception as e: 
		print(e)
		print('cannot decrypt rsa')
		
	try:
		return out
	except Exception as e: 
		print(e)
		print('cannot return rsa decryption')

# Shortens a string if len>20
def shorten(string):
	if len(string) > 20: return string[:40] + "..."
	else: return string

# Accept and parse incoming data over the connection.
while True:
	conn, addr = serv.accept()
	from_client = []
	return_msg = ''

	# Incoming AES message format:
	# messageType#nonce#ciphertext
	# e.g. 0#10101001...#01010111...

	# Incoming RSA message format:
	# messageType#
	# e.g. 1#
	
	while True:
		data = conn.recv(4096).decode("utf-8")	
		if not data: break
		from_client = data.split("#####");
		try:
#			print(data)
			selection = from_client[0]		
			value = from_client[1]
		except:
			print("Cannot parse request from client.")

		# Debug interface
		# print(from_client)
		# print("selection=",selection)
		# print("value=",value)

		# Successful connection.
		if(selection=="0"):
			print("\nClient successfully connected at " + value + ":" + str(portNum) + "\n")
			return_msg="Successfully connected to server at " + value + ":" + str(portNum)
		
		# Request to decrypt AES_EAX message
		elif(selection=="1"):
			print("Decrypting with AES...\n")
			try:
				nonce = from_client[1]
				ciphertext = from_client[2]
				tag = from_client[3]
				message = encryptAES_EAX(nonce, ciphertext, tag)								
				print("Decrypted message:\n" + message.decode())
				return_msg="Message was decrypted by server: " + str(message)
			except Exception as e: 
				print(e)
				print("Cannot parse AES paramenters from client")

		# Request to decrypt AES_CBC message
		elif(selection=="2"):
			print("Decrypting with AES...\n")
			try:
				iv = from_client[1]
				ciphertext = from_client[2]
				message = encryptAES_CBC(iv, ciphertext)								
				print("Decrypted message:\n" + message.decode())
				return_msg="Message was decrypted by server: " + str(message)
			except Exception as e: 
				print(e)
				print("Cannot parse AES paramenters from client")

		
		# Request to decrypt RSA message.
		elif(selection=="3"):
			print("Decrypting with RSA...\n")
			try:
				ciphertext = from_client[1]
				message = decryptRSA(ciphertext)
				print("Decrypted message:\n" + message.decode())
				return_msg="Message was decrypted by server: " + str(message)
			except Exception as e: 
				print(e)
				print("Cannot parse RSA ciphertext from client")
		
		# Request to terminate session.
		elif(selection=="4"):
			conn.close()
			print ('Client disconnected')
			break
		
		else:
			return_msg = "Invalid server request."
			print(return_msg)
		
		# Send return message back to client 
		conn.send(bytes(return_msg, 'utf-8'))
