from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

key = b'SECURITYKEY12345'  # 16 bytes for AES-128
plaintext = b'CIEDAONDNTFFIAA'

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
encoded = base64.b64encode(ciphertext)
print("AES Encrypted:", encoded)

# Decrypt
decoded = base64.b64decode(encoded)
decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
print("Decrypted:", decrypted.decode())
