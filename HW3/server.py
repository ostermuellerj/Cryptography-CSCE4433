#JOHN OSTERMUELLER
#010887505
#Cryptography HW3

import socket

# PyCryptodome:
# pip install pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import codecs
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html?highlight=aes
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html?highlight=rsa

portNum = 8012
serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind(('127.0.0.1', portNum))
serv.listen(5)

# Generate AES key file (Alice/Client and Bob/Server can both access, we assume it is secure)
key_file = open("key_file.bin", "wb")
key = get_random_bytes(16)
print("\nAES shared key generated: ")
print(key)
key_file.write(key) 
key_file.close()

print("\nWaiting for connection on 0.0.0.0:" + str(portNum)+" ...")

# Local encryption/decryption testing:
#cipher = AES.new(key, AES.MODE_EAX)
#nonce = cipher.nonce
#ciphertext, tag = cipher.encrypt_and_digest("0101010101".encode("utf-8"))
#cipher2 = AES.new(key, AES.MODE_EAX, nonce=nonce)
#out = cipher2.decrypt(ciphertext)
#print(type(out))
#print(out.decode())

# Decrypt an AES-encrypted message given the nonce, ciphertext, and tag
def decryptAES(nonce, ciphertext, tag):
	print("RECIEVED FROM CLIENT...")
	print("Nonce: " + str(nonce))
	print("Ciphertext: " + str(ciphertext))
	print("Tag: " + str(tag) + "\n")		
	
	try:
		cipher2 = AES.new(key, AES.MODE_EAX, nonce=nonce.encode("latin-1"))		
	except Exception as e: 
		print(e)
	
	try:
#		out = cipher2.decrypt(ciphertext.encode("latin-1"))
		out = cipher2.decrypt_and_verify(ciphertext.encode("latin-1"), tag.encode("latin-1"))
	except Exception as e: 
		print(e)
		print('cannot decrypt')
		
	try:
		return out
	except Exception as e: 
		print(e)
		print('cannot return decryption')
		
def decryptRSA(ciphertext):
	return ciphertext

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
		from_client = data.split("#");
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
		
		# Request to decrypt AES message
		elif(selection=="1"):
			print("Decrypting with AES...\n")
			try:
				nonce = from_client[1]
				ciphertext = from_client[2]
				tag = from_client[3]
				message = decryptAES(nonce, ciphertext, tag)								
				print("Decrypted message:\n" + message.decode())
				return_msg="Message was decrypted by server: " + str(message)
			except Exception as e: 
				print(e)
				print("Cannot parse AES paramenters from client")
		
		# Request to decrypt RSA message.
		elif(selection=="2"):
			print("Decrypting with RSA...")
			print("Decrypted message:\n" + decryptRSA(from_client[1]))
			return_msg="Message was decrypted."
		
		# Request to terminate session.
		elif(selection=="3"):
			conn.close()
			print ('Client disconnected')
			break
		
		else:
			return_msg = "Invalid server request."
			print(return_msg)
		
		# Send return message back to client 
		conn.send(bytes(return_msg, 'utf-8'))
