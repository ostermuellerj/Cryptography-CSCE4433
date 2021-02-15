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

portNum = 8011
serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind(('127.0.0.1', portNum))
serv.listen(5)

# Generate AES Key File (Alice/Client and Bob/Server can both access)
key_file = open("key_file.bin", "wb")
key = get_random_bytes(16)
#print(get_random_bytes(16))
#key = b'\xb0\x90D\xeb\xc6\xf2\xbb\x96\x18\x1c\xb2\x95\xb9L\x1e\xd1'
print("\nAES shared key generated: ")
print(key)
#print("str(AES shared key:)")
#print(str(key))
key_file.write(key) 
key_file.close()

print("\nWaiting for connection on 0.0.0.0:" + str(portNum)+" ...")


#cipher = AES.new(key, AES.MODE_EAX)
#nonce = cipher.nonce
#ciphertext, tag = cipher.encrypt_and_digest("0101010101".encode("utf-8"))
#cipher2 = AES.new(key, AES.MODE_EAX, nonce=nonce)
#out = cipher2.decrypt(ciphertext)
#print(type(out))
#print(out.decode())

def decryptAES(nonce, ciphertext, tag):
#	print("AES shared key: " + str(key))
#	print(key)
	print("RECIEVED FROM CLIENT...")
	print("Nonce: " + str(nonce))
#	print(nonce)
#	print(type(nonce))
	print("Ciphertext: " + str(ciphertext))
#	print(ciphertext)
	print("Tag: " + str(tag) + "\n")		
#	print(tag)		
	
	try:
#		cipher = AES.new('0101010101010101'.encode("utf-8"), AES.MODE_EAX)
#		print("encoded nonce:")
#		print(nonce.encode())
		cipher2 = AES.new(key, AES.MODE_EAX, nonce=nonce.encode("latin-1"))		
	except Exception as e: 
		print(e)
	
	try:
		out = ""
		out = cipher2.decrypt(ciphertext.encode("latin-1"))
#		print(out)
		#out = cipher.decrypt_and_verify(ciphertext.decode("utf-8"), tag.decode("utf-8"))
	except Exception as e: 
		print(e)
		print('cannot decrypt')
		
	try:
#		print(type(out))
#		print(out)		
		return out
	except Exception as e: 
		print(e)
		print('cannot return decryption')
		
def decryptRSA(ciphertext):
	return ciphertext

while True:
	conn, addr = serv.accept()
	from_client = []
	return_msg = ''

	# incoming AES message format:
	# messageType#nonce#ciphertext
	# e.g. 0#10101001...#01010111...

	# incoming RSA message format:
	# messageType#
	# e.g. 1#
	
	while True:
		data = conn.recv(4096).decode("utf-8")	
		if not data: break
		from_client = data.split("#");
		try:
#			print("data : " + str(data))
#			print(data)
			selection = from_client[0]		
			value = from_client[1]
		except:
			print("Cannot parse request from client.")

		# debug
		# print(from_client)
		# print("selection=",selection)
		# print("value=",value)

		if(selection=="0"):
			print("\nClient successfully connected at " + value + ":" + str(portNum) + "\n")
			return_msg="Successfully connected to server at " + value + ":" + str(portNum)
		elif(selection=="1"):
			print("Decrypting with AES...\n")
			# message = decryptAES(from_client[1], from_client[2], from_client[3])
			try:
				nonce = from_client[1]
				ciphertext = from_client[2]
				tag = from_client[3]
				message = decryptAES(nonce, ciphertext, tag)								
				print("Decrypted message:\n" + str(message))
				return_msg="Message was decrypted: " + str(message)
			except Exception as e: 
				print(e)
				print("Cannot parse AES paramenters from client")
		elif(selection=="2"):
			print("Decrypting with RSA...")
			print("Decrypted message:\n" + decryptRSA(from_client[1]))
			return_msg="Message was decrypted."
		elif(selection=="3"):
			conn.close()
			print ('Client disconnected')
			break
		else:
			return_msg = "Invalid server request."
			print(return_msg)
		
		conn.send(bytes(return_msg, 'utf-8'))
