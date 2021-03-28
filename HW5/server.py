#JOHN OSTERMUELLER
#010887505
#Cryptography HW5

import socket
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Signature import pkcs1_15

portNum = 8000
serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind(('127.0.0.1', portNum))
serv.listen(5)

#Generate shared key for HMAC
HMAC_key_file = open("HMAC_key_file.bin", "wb")
HMAC_key = get_random_bytes(16)
HMAC_key_file.write(HMAC_key) 
HMAC_key_file.close()

# Generate RSA public key and place in key file. 
RSA_key = RSA.generate(2048)
print("\nRSA public key generated (hidden).")
public_key = RSA_key.export_key()
RSA_key_file = open("RSA_key_file.pem", "wb")
RSA_key_file.write(public_key)
RSA_key_file.close()

print("\nWaiting for connection on 0.0.0.0:" + str(portNum)+" ...")

# Verify an HMAC given a message and shared key
def verifyHMAC(message, hmac):
	print("RECIEVED FROM CLIENT...")
	print("Message: " + shorten(message))
	print("HMAC: " + shorten(str(hmac)))
	
	h = HMAC.new(HMAC_key, digestmod=SHA256)
	h.update(message.encode('utf-8'))	
	
	try:
		h.hexverify(hmac)
		result = "The message is authentic"
	except ValueError:
		result = "The message or key is invalid"
	print(result)
	return result

# Verify an RSA signature given a message and shared key
def verifySignature(message, signature):
	print("RECIEVED FROM CLIENT...")
	print("Message: " + shorten(message))
	print("Signature: " + shorten(str(signature)))	
	
	try:
		h = SHA256.new(message.encode('utf-8'))
		pkcs1_15.new(RSA_key).verify(h, signature)
		result = "The signature is valid"
	except ValueError:
		result = "The signature or key is invalid"
	print(result)
	return result

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
		
		# Request to authenticate HMAC.
		elif(selection=="1"):
			print("Authenticating HMAC...\n")
			try:
				message = from_client[1]
				hmac = from_client[2]
				try:	
					result = verifyHMAC(message, hmac.encode('latin-1').decode('utf-8'))
				except Exception as e: 
					print(e)
					print('cannot verify hmac')
				print("Message:\n" + message)
				print(result)
			except Exception as e: 
				print(e)
				print("Cannot parse HMAC from client")

		# Request to authenticate RSA signature.
		elif(selection=="2"):
			print("Authenticating RSA signature...\n")
			try:
				message = from_client[1]
				signature = from_client[2]	
				
				signature = signature.encode('latin-1')
				result = verifySignature(message, signature)
				print("Message:\n" + message)
				print(result)
			except Exception as e: 
				print(e)
				print("Cannot parse RSA signature from client")		
		
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
