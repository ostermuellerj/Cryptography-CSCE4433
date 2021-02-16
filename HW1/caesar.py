# JOHN OSTERMUELLER 010887505
# HW1 - ENHANCED CAESAR CIPHER
# CSCE 4433 CRYPTOGRAPHY
# SPRING 2021

alphabet = ['a', 'b', 'c', 'd', 'e', 'f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
dictFile = "sample.txt"
dictionary = []

# Parse text file as list of strings
def parseDict():
	f = open(dictFile, "r")
	for line in f:
		for word in line.split():
			dictionary.append(word)
	# Debug
	# print(dictionary)

parseDict()

# Get input key and check if 0 < key < 26
def getKey():
	key = 0
	while(True):
		key = input("Please enter a key:\n")
		try:
			key = int(key)
			if(key > 25):
				print("Key must be less than 26.")
				continue
			elif(key < 0):
				print("Key must be positive.")
				continue
			else:
				break
		except ValueError:
			print("Key must be a positive integer less than 26.")
			continue
	return key

# Rotate each char in a given string by a given key	
def rotate(key, string):
	out = ""
	for c in string:
		index = 0
		try:
			index = alphabet.index(c)
		except ValueError:
			out+=c
			continue	
		out+= alphabet[(index+key)%26]	
	return out

# Encrypt a message with a key (forwards rotation)
def encrypt():
	message = input("Please input a message to encrypt:\n")
	cyphertext = rotate(getKey(), message)
	print("Encrypted cyphertext:\n" + cyphertext)

# Encrypt a message with a key (backwards rotation)
def decrypt():
	cyphertext = input("Please input a cyphertext message to decrypt:\n")
	message = rotate(-getKey(), cyphertext)
	print("Encrypted cyphertext:\n" + message)

# For each possible key (0-26), check each decrypted word in a given cipher 
# message against the dictionary. If each word in a decrypted message matches
# a word in the dictionary, return the current key.
def dictDecrypt():
	cyphertext = input("Please input a cyphertext message to decrypt:\n")
	for key in range(27):
		cipherWords = rotate(key, cyphertext).split()
		matches = 0
		for word in cipherWords:
			if(word in dictionary):
				print("Word found")
				matches+=1
		if(matches == len(cipherWords)):
			key = -key%26
			print("Key found: " + str(key))
			return key
	print("Key not found.")
		
def prompt():
	inp = input("Select an option below:\n  0: Encrypt\n  1: Decrypt with key\n  2: Decrypt with dictionary\n")
	if(inp == '0'):
		encrypt()
		cont()
	elif(inp == '1'):
		decrypt()
		cont()
	elif(inp == '2'):
		dictDecrypt()
		cont()
	else:
		print("Invalid input.")
		prompt()

def cont():
	inp = input("Would you like to continue? (y/n) ")
	if(inp == 'y'):
		prompt()
	elif(inp == 'n'):
		exit()
	else:
		print("Invalid input.")
		cont()

prompt()
