import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes

for i in range(100):
	HMAC_key = get_random_bytes(16)
	h = HMAC.new(HMAC_key, digestmod=SHA256)
	message = b'Hello'
	h.update(message)
	print("h.hexdigest():")
	print(h.hexdigest())
	#Validate
	h1 = HMAC.new(HMAC_key, digestmod=SHA256)
	h1.update(message)
	try:
		h1.hexverify(h.hexdigest())
		print("The message is authentic")
	except ValueError:
		print("The message or key is invalid")
