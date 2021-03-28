from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes

def findCollision(showResults):
	i = 0
	while(True):
		m1 = get_random_bytes(16)
		h1 = SHA256.new(m1)

		m2 = get_random_bytes(16)
		h2 = SHA256.new(m2)

		if(h1.digest()[0] == h2.digest()[0]):
			if(showResults):
				print("Matching hash value found for m1 and m2 after " + str(i) + " iterations:")
				print("Hash value: " + str(h1.digest()[0]))
				print("m1: " + str(m1.decode("latin-1")))
				print("m2: " + str(m2.decode("latin-1")))
			return(i)
		i+=1

n = 20
def findAverageCollisions():
	total = 0.0
	for k in range(n):
		total += findCollision(False)
	return total/n
	
#findCollision(True)
print("Average number of trials to find a collision (" + str(n) + " iterations): " + str(findAverageCollisions()))
