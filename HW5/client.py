# JOHN OSTERMUELLER
# 010887505
# Cryptography HW5

import socket
import time
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Signature import pkcs1_15

# declare+connect socket
address='127.0.0.1'
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((address, 8000))

# Generates HMAC of message using shared key and sends HMAC & message to server
def generateHMAC(message):
	key_file = open("HMAC_key_file.bin", "rb")
	key = key_file.read(16)
	key_file.close()
	h = HMAC.new(key, digestmod=SHA256)
	h.update(message.encode('utf-8'))
	hmac = h.hexdigest().encode('utf-8')
	#Corrupt HMAC:
	#hmac += "4".encode('utf-8')
	print("Generated HMAC:" + str(hmac))
		
	# Send message and HMAC to server
	send("1#####" + message + "#####" + hmac.decode('latin-1'))

# Generates signature of message using shared RSA key
def signRSA(message):
	key_file = open("RSA_key_file.pem")
	public_key = RSA.import_key(key_file.read())
	key_file.close()
	h = SHA256.new(message.encode('utf-8'))
	signature = pkcs1_15.new(public_key).sign(h)
	#Corrupt signature:
	#signature+="4".encode('utf-8')
	print("Generated signature: " +shorten(str(signature)))	

	# Send message and signature to server
	send("2#####" + message + "#####" + signature.decode("latin-1"))

# Send connection request, wait, then print response
def main():
	client.send(bytes("0#####"+address, 'utf-8'))
	time.sleep(1)
	print("\n"+str(client.recv(4097)).replace("b'","").replace("'","")+"\n")

	menu()

def menu():
	while True:
		ciphertext = ""
		inp = input("Select an authentication scheme:\n1 - HMAC + SHA256\n2 - RSA Signature\n\n")
		if(inp=="3"):
			send("3#")
			client.close()
			exit()
		elif(inp=="1"):
			message = input("Please enter an 18-byte message to send to Bob:\n")
			generateHMAC(message)
		elif(inp=="2"):
			message = input("Please enter an 18-byte message to send to Bob:\n")
			signRSA(message)
		else:
			print("Please enter valid input, or enter 3 to exit e.g. \"1\", \"2\", \"3\", ...)")	

# Send a request to the server
# request = str = message to be sent
def send(request):
	print("\nSENDING REQUEST:")
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
