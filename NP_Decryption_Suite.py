from Crypto import Cipher
from Crypto.Cipher import AES
from Crypto.Hash import SHA512, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import Salsa20
from base64 import b64encode, b64decode

def NP_Decryption_Suite_V2(password, store):

    # Initialization and decoding of data
    salt = store['salt']
    salt = salt[salt.find("$$")+2 : salt.find("$$", salt.find("$$") + 1)]
    salt = b64decode(salt.encode())

    stream_nonce = store['stream_nonce']
    stream_nonce = stream_nonce[stream_nonce.find("$$")+2 : stream_nonce.find("$$", stream_nonce.find("$$") + 1)]
    stream_nonce = b64decode(stream_nonce.encode())
    
    ciphertext = store['ciphertext']
    ciphertext = ciphertext[ciphertext.find("$$")+2 : ciphertext.find("$$", ciphertext.find("$$") + 1)]
    ciphertext = b64decode(ciphertext.encode())
    
    init_vector = store['init_vector']
    init_vector = init_vector[init_vector.find("$$")+2 : init_vector.find("$$", init_vector.find("$$") + 1)]
    init_vector = b64decode(init_vector.encode())

    tag = store['hmac']
    tag = tag[tag.find("$$")+2 : tag.find("$$", tag.find("$$") + 1)]

    # HMACing the salt with the password to stretch the key
    hash1 = HMAC.new(key=password, digestmod=SHA512).update(salt).digest()
    for i in range(5 * 10**4):
        hash1 = HMAC.new(key=password, digestmod=SHA512).update(salt).digest()

    # Encryption of the Hashed Random Salt with a stream cipher
    stream_cipher = Salsa20.new(key = pad(password, 16), nonce=stream_nonce)
    encrypted_salt = stream_cipher.encrypt(hash1)

    # Key Derivation function with encrypted salt
    key = scrypt(password, encrypted_salt, key_len=16, N=2**15, r=8, p=1, num_keys=1)

    # Check HMAC tag
    try:
        HMAC.new(key=key, digestmod=SHA512).update(ciphertext).hexverify(tag)
    except ValueError:
        # Replace the exit() function
        # exit("The password is incorrect or the data has been tampered with!!")
        return "HMAC_ERROR"

    # Block cipher - Decryption of the payload
    block_cipher = AES.new(key, AES.MODE_CBC, init_vector)
    data = unpad(block_cipher.decrypt(ciphertext), 16)
    
    # Masking of the key so it cannot be extracted from memory
    # after the function has finished using the key
    for i in key:
      i = 'a'.encode()
    del(key)
    del(block_cipher)

    return data
