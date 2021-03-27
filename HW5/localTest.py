from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Random import get_random_bytes

#Generate/validate HMAC test:
print("Generate/validate HMAC test:")
#Generate
secret = b'secretkey'
h = HMAC.new(secret, digestmod=SHA256)
message = b'Hello'
h.update(message)
print("h.hexdigest():")
print(h.hexdigest())
#Validate
h1 = HMAC.new(secret, digestmod=SHA256)
h1.update(message)
try:
	h1.hexverify(h.hexdigest())
	print("The message is authentic")
except ValueError:
	print("The message or key is invalid")

#Generate/verify RSA digital signature:
print("Generate/verify RSA digital signature test:")
#Generate
message = b'Hello'
key = RSA.generate(2048)
h = SHA256.new(message)
signature = pkcs1_15.new(key).sign(h)
#Validate
h1 = SHA256.new(message)
try:
	pkcs1_15.new(key).verify(h1, signature)
	print("The signature is valid")
except ValueError:
	print("The signature or key is invalid")
