# Encrypted client-server socket communication

This program implements AES (optional EAX or CBC mode) and RSA (single key, not secure) encryption for user-inputted messages over a socket connection between two programs.

Client: Alice
Server: Bob

I: Encryption/decryption with AES, 128-bit key, CBC mode
Assume Alice and Bob have a shared secret key.
- Alice encrypts 18-byte message m (inputted from cmd line) which is encrypted as ciphertext.
- Message is sent to Bob
- Bob reads and decrypts ciphertext, then prints ciphertext and message m
	
II: Encryption/decryption with RSA (using public key only), 2048-bit key
- Bob sends public key to Alice
- Alice encrypts 18-byte message (inputted from cmd line) using Bob's public key.
- Message is sent to bob
- Bob reads and decrypts ciphertext, then prints ciphertext and message m

III: Compare performance of AES and RSA under different parameters (seperate program)
- Take a 7-byte message manually input from the command line.
- For 100 iterations, compute average runtimes for:
	- AES key sizes 128-bit, 192-bit, 256-bit, measure average time of encryption 
	 AND average time of decryption for EACH key size (6 measurements)
	- RSA key sizes 1024-bit, 20148-bit, 4096-bit, measure average time of encryption 
	 AND average time of decryption for EACH key size (6 measurements)	
