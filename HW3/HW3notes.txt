Implement RSA and AES encryption over a socket connection between two programs.

part 1: Encryption/decryption with AES, 128-bit key, CBC mode
Assume Alice and Bob have a shared secret key.
- Alice encrypts 18-byte message m (inputted from cmd line) which is encrypted as ciphertext.
- Message is sent to Bob
- Bob reads and decrypts ciphertext, then prints ciphertext and message m

	Client: Alice
	Server: Bob
	A encrypts and sends to B, B decrypts and prints ciphertext and message.
	
part 2: Encryption/decryption with RSA, 2048-bit key
- Bob sends public key to Alice
- Alice encrypts 18-byte message (inputted from cmd line) using Bob's public key.
- Message is sent to bob
- Bob reads and decrypts ciphertext, then prints ciphertext and message m

	Client: Alice
	Server: Bob
	A encrypts and sends to B, B decrypts and prints ciphertext and message.

part 3: Compare performance of AES and RSA under different parameters (seperate program)
- Take a 7-byte message manually input from the command line.
- For AES key sizes 128-bit, 192-bit, 256-bit, measure average time of encryption 
	AND average time of decryption for EACH key size (6 measurements)
- For RSA key sizes 1024-bit, 20148-bit, 4096-bit, measure average time of encryption 
	AND average time of decryption for EACH key size (6 measurements)	
- Print the 12 measurements