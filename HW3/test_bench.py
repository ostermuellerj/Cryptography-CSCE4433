#JOHN OSTERMUELLER
#010887505
#Cryptography HW3

import time
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Crypto.PublicKey import RSA

init = 0

n = 100

def main():
	message = input("Enter a 7-byte message:\n")
	
	init = time.time()

	#first element is encryption time, second element is decryption time
	AES128_sums = [0, 0]
	AES192_sums = [0, 0]
	AES256_sums = [0, 0]
	
	RSA1024_sums = [0, 0]
	RSA2048_sums = [0, 0]
	RSA4096_sums = [0, 0]

	for i in range(n):
		print(str(i+1) + "/" + str(n))
		
		#AES 128
		results = doAES(message, 16)
		AES128_sums[0] += results[0]
		AES128_sums[1] += results[1]

		#AES 192
		results = doAES(message, 24)
		AES192_sums[0] += results[0]
		AES192_sums[1] += results[1]

		#AES 256
		results = doAES(message, 32)
		AES256_sums[0] += results[0]
		AES256_sums[1] += results[1]

		#RSA 1024
		results = doRSA(message, 1024)
		RSA1024_sums[0] += results[0]
		RSA1024_sums[1] += results[1]

		#RSA 2048
		results = doRSA(message, 2048)
		RSA2048_sums[0] += results[0]
		RSA2048_sums[1] += results[1]

		#RSA 4096
		results = doRSA(message, 4096)
		RSA4096_sums[0] += results[0]
		RSA4096_sums[1] += results[1]
		
		
	AES128_sums[0]/=n
	AES128_sums[1]/=n
	
	AES192_sums[0]/=n
	AES192_sums[1]/=n
	
	AES256_sums[0]/=n
	AES256_sums[1]/=n
	
	RSA1024_sums[0]/=n
	RSA1024_sums[1]/=n

	RSA2048_sums[0]/=n
	RSA2048_sums[1]/=n

	RSA4096_sums[0]/=n
	RSA4096_sums[1]/=n
	
	print("AES 128 e: " + str(AES128_sums[0]))
	print("AES 128 d: " + str(AES128_sums[0])+"\n")

	print("AES 192 e: " + str(AES192_sums[0]))
	print("AES 192 d: " + str(AES192_sums[0])+"\n")

	print("AES 256 e: " + str(AES256_sums[0]))
	print("AES 256 d: " + str(AES256_sums[0])+"\n")

	print("RSA 1024 e: " + str(RSA1024_sums[0]))
	print("RSA 1024 d: " + str(RSA1024_sums[0])+"\n")

	print("RSA 2048 e: " + str(RSA2048_sums[0]))
	print("RSA 2048 d: " + str(RSA2048_sums[0])+"\n")

	print("RSA 4096 e: " + str(RSA4096_sums[0]))
	print("RSA 4096 d: " + str(RSA4096_sums[0])+"\n")
	
	print("Total time: " + str(time.time()-init))
	
	f = open("testbench.txt", "w")
	f.write("AES 128 e: " + str(AES128_sums[0])+"s\n")
	f.write("AES 128 d: " + str(AES128_sums[0])+"s\n")

	f.write("AES 192 e: " + str(AES192_sums[0])+"s\n")
	f.write("AES 192 d: " + str(AES192_sums[0])+"s\n")

	f.write("AES 256 e: " + str(AES256_sums[0])+"s\n")
	f.write("AES 256 d: " + str(AES256_sums[0])+"s\n")

	f.write("RSA 1024 e: " + str(RSA1024_sums[0])+"s\n")
	f.write("RSA 1024 d: " + str(RSA1024_sums[0])+"s\n")

	f.write("RSA 2048 e: " + str(RSA2048_sums[0])+"s\n")
	f.write("RSA 2048 d: " + str(RSA2048_sums[0])+"s\n")

	f.write("RSA 4096 e: " + str(RSA4096_sums[0])+"s\n")
	f.write("RSA 4096 d: " + str(RSA4096_sums[0])+"s\n")
	
	f.write("\nTotal time: " + str(time.time()-init) + "s\n")

	f.close()



def doAES(message, keySize):
	# Encrypt
	encryptStart = time.time()
	key = get_random_bytes(keySize)
	cipher = AES.new(key, AES.MODE_CBC)
	ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
	iv = cipher.iv
	encryptTime = time.time()-encryptStart

	#Decrypt
	decryptStart = time.time()
	cipher2 = AES.new(key, AES.MODE_CBC, iv)
	pt = unpad(cipher2.decrypt(ciphertext), AES.block_size)
#	print(pt.decode())
	decryptTime = time.time()-decryptStart
	
	return (encryptTime, decryptTime)

def doRSA(message, keySize):
	# Encrypt
	encryptStart = time.time()
	RSA_key = RSA.generate(keySize)
	RSA_cipher = PKCS1_OAEP.new(RSA_key)
	RSA_ciphertext = RSA_cipher.encrypt(message.encode())
	encryptTime = time.time()-encryptStart

	#Decrypt
	decryptStart = time.time()
	RSA_cipher2 = PKCS1_OAEP.new(RSA_key)
	out = RSA_cipher2.decrypt(RSA_ciphertext).decode() 
#	print(out)
	decryptTime = time.time()-decryptStart
	
	return (encryptTime, decryptTime)

main()
