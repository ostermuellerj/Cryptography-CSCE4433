#JOHN OSTERMUELLER
#010887505
#Cryptography HW5

# This program demonstrates the avg runtime of: 
#	1. HMAC generation 
#	2. RSA signature generation 
#	3. RSA signature verification

import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes

# Make HMAC key
HMAC_key = get_random_bytes(16)

# Make RSA key
RSA_key = RSA.generate(2048)

n = 100
message=""

# Run tests for n iterations
def main():
	HMAC_gen_sum = 0.0
	RSA_gen_sum = 0.0
	RSA_verify_sum = 0.0
	message = input("Enter a 7-byte message:\n")
	for i in range(n):
		print(str(i) + "/" + str(n))
		HMAC_gen_sum += genHMAC()
		RSA_results = gen_and_verifyRSA()
		RSA_gen_sum += RSA_results[0]
		RSA_verify_sum += RSA_results[1]
	print("Average HMAC generation time: " + str(HMAC_gen_sum/n))
	print("Average RSA signature generation time: " + str(RSA_gen_sum/n))
	print("Average RSA signature verification time: " + str(RSA_verify_sum/n))
	
# Generate HMAC, returns runtime
def genHMAC():
	start = time.time()
	h = HMAC.new(HMAC_key, digestmod=SHA256)
	h.update(message.encode('utf-8'))
	return time.time() - start

# Generate and verify RSA signature, returns runtime for each
def gen_and_verifyRSA():
	start = time.time()
	h = SHA256.new(message.encode('utf-8'))
	signature = pkcs1_15.new(RSA_key).sign(h)
	genTime = time.time() - start

	start = time.time()
	h1 = SHA256.new(message.encode('utf-8'))
	try:
		pkcs1_15.new(RSA_key).verify(h1, signature)
	except ValueError:
		print("The signature or key is invalid")
	verifyTime = time.time() - start
	return (genTime, verifyTime)
	
main()
