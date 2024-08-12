import math
from timeit import default_timer as timer
from Crypto.Protocol.KDF import PBKDF2 # pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA512


# modular exponantiation
"""
 - this should not be used as its inefficient in large numbers

def modExp0(x, y, z):
    return math.fmod(math.pow(x, y), z) #x^y mod z
"""

def modExponent(x, y, z):
    latest_result = None
    i = 1
    while i <= y:
        if i == 1:
            latest_result = math.fmod(math.pow(x, i), z)
        else:
            latest_result = math.fmod(x * latest_result, z)

        i += 1

    return latest_result

def derivePublicSecret(base, mod, secret): # these base, mod & num values can be publily known, it wont impair the algorithm
    return modExponent(base, secret, mod)
    
def deriveSharedSecret(public_key, secret, mod):
    return modExponent(public_key, secret, mod)


def deriveKeyFromSharedSecret(shared_secret, salt):
    password_str = str(shared_secret)  
    password_bytes = password_str.encode('utf-8') 

    #salt = get_random_bytes(16)

    key = PBKDF2(password_bytes, salt, 32, count=1000000, hmac_hash_module=SHA512)
    return key


def encryptStringWithSharedKey(string, shared_key):
    cipher = AES.new(shared_key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(pad(string, AES.block_size))

    # Store the IV and ciphertext together
    iv = cipher.iv
    encrypted_message = iv + ciphertext
    return encrypted_message

def decryptCiphertextWithSharedKey(ciphertext, shared_key):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]

    # Create a cipher object for decryption
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message

# values below are just examples, please dont use the same values every time
base = 5
mod = 7643 # modulus should be a large number to prevent brute force attacks, also should be a prime number
secret1 = 628496 # your secret
secret2 = 537214 # their secret

public1 = derivePublicSecret(base, mod, secret1) # your public secret
public2 = derivePublicSecret(base, mod, secret2) # their public secret

# you exchange public secrets with him

private1 = deriveSharedSecret(public2, secret1, mod) # their public key + your secret

private2 = deriveSharedSecret(public1, secret2, mod) # your public key + their secret

# both of these values should be the same, even though they were never passed to each other

print(private1, private2)

salt = get_random_bytes(16) # this will also be shared, its just used to prevent dictionary attacks

shared_key = deriveKeyFromSharedSecret(private1, salt) # Now we can use this key to encrypt messages :)

message = "my super secret message"
encrypted_message = encryptStringWithSharedKey(message, shared_key)

print(f'Encrypted message: {encrypted_message.hex()}')

decrypted_message = decryptCiphertextWithSharedKey(encrypted_message, shared_key)

print(f'Decrypted message: {decrypted_message.decode()}')