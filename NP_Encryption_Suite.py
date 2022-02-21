from Crypto.Cipher import AES
from Crypto.Hash import SHA512, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import Salsa20
from base64 import b64encode, b64decode

def NP_Encryption_Suite_V2(password, data):
    # Initialization of a dictionary for storage
    store = {}

    # Generation of salt
    salt = get_random_bytes(16)
    store['salt'] = salt

    # HMACing the salt with the password to stretch the key
    hash1 = HMAC.new(key=password, digestmod=SHA512).update(salt).digest()
    for i in range(5 * 10**4):
        hash1 = HMAC.new(key=password, digestmod=SHA512).update(salt).digest()

    # Encryption of the Hashed Random Salt with a stream cipher
    stream_cipher = Salsa20.new(key = pad(password, 16))
    stream_cipher_nonce = stream_cipher.nonce
    encrypted_salt = stream_cipher.encrypt(hash1)
    
    store['stream_nonce'] =  "$$" + b64encode(stream_cipher_nonce).decode() + "$$"

    # Derivation of key with the help of a salt encrypted by a stream cipher ->(BIN)
    key = scrypt(password, encrypted_salt, key_len=16, N=2**15, r=8, p=1, num_keys=1)

    # Encryption of the data with a block ciper from the derived key ->(BIN)
    block_cipher = AES.new(key, AES.MODE_CBC)
    store['init_vector'], store['ciphertext'] = block_cipher.iv, block_cipher.encrypt(pad(data, 16))

    # Production of HMAC ->(HEX)
    mac = HMAC.new(key, digestmod=SHA512).update(store['ciphertext']).hexdigest()
    store['hmac'] = "$$" + mac + "$$"

    # Padding of the data as transferring via SMTP may introduce unwanted spaces
    store['ciphertext'] = "$$" + b64encode(store['ciphertext']).decode() + "$$"
    store['init_vector'] = "$$" + b64encode(store['init_vector']).decode() + "$$"
    store['salt'] = "$$" + b64encode(store['salt']).decode() + "$$"

    return store
