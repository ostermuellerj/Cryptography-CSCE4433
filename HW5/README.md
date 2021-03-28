# Digital Signature and HMAC
Instead of using mactext and sigtext files to demonstrate the ability to corrupt, I added seperate lines in the HMAC and RSA generation functions to manually corrupt the HMAC or signature, respectively.

I. Authentication with HMAC, SHA256.
- Alice and Bob have 16-byte shared secret key (read from file).
- Alice generates HMAC of 18-byte message (inputted from the cmd line) and writes the message and the HMAC into "mactext".
- Bob reads message and HMAC, then verifies HMAC
	
II. Digital signature with RSA and 2048-bit key.
- Bob gets Alice's public key.
- Alice signs 18-byte message using her private key to get a signature then writes message and signature into "sigtext"
- Bob reads message & signature, verifies signature with Alice's public key
	
III. Performance testing of HMAC and digital signature.
- Get 7-byte message from cmd line.
- HMAC (SHA256, 16-byte key) of message is generated 100 times, the generation of each key is timed in order to calculate the average.
- RSA (2048-bit key) digital signature of the message is generated then verified 100 times, timed to calculate average generation/verification time.
- The program outputs averages for (1) HMAC generation time, (2) RSA digital signature generation time, and (3) signature verification time.
	 
IV. Hash collision and birthday paradox.
- Assume a hash fuction H(), where H(m) = {First 8 bits of SHA-256(m)}
- Hash values for random messages are generataed using this special hash function until two messages are found that generate the same hash valaue. These two messages and the equivalent hash value are outputted.
- This process is repeated for 20 iterations. The program finds the average number of trials needed to find a collision.
