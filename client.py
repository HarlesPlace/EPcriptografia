from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes,hmac
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os, requests

class EncryptionManager:
    def __init__(self):
        key = os.urandom(32)
        IV = os.urandom(16)
        print("Key: "+str(key))
        print("IV: "+str(IV))
        aes_context = Cipher(algorithms.AES(key), modes.CTR(IV), backend=default_backend())
        self.encryptor = aes_context.encryptor()
        self.decryptor = aes_context.decryptor()
    
    def updateEncryptor(self, plaintext):
        return self.encryptor.update(plaintext)
    
    def finalizeEncryptor(self):
        return self.encryptor.finalize()
    
    def updateDecryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)
    
    def finalizeDecryptor(self):
        return self.decryptor.finalize()

# Auto generate key/IV for encryption
manager = EncryptionManager()
mac = os.urandom(32)

email = input("Digite seu email: ")
senha = input("Digite sua senha: ")

plaintexts = [(email+"^"+senha).encode('utf-8')]
print(plaintexts)

ciphertexts = []

for m in plaintexts:
    ciphertexts.append(manager.updateEncryptor(m))
ciphertexts.append(manager.finalizeEncryptor())

print("cifrados:")
print(ciphertexts)
print(ciphertexts[0])

hmac = hmac.HMAC(mac, hashes.SHA256(), backend=default_backend()) 
hmac.update() 
hmac.finalize(ciphertexts[0])
r = requests.post('http://localhost:5000/login', data={'session_keys': b64encode(manager.key+manager.key+mac).decode('ascii'),'cyphertext': b64encode(ciphertexts[0]).decode('ascii'),'hmac': b64encode(hmac).decode('ascii')})
r.status_code
r.cookies['session_id']
#for c in ciphertexts:
#    print("Recovered", manager.updateDecryptor(c))
#print("Recovered", manager.finalizeDecryptor())