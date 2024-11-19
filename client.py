from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes,hmac
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os, requests

class EncryptionManager:
    def __init__(self):
        self.key = os.urandom(32)
        self.IV = os.urandom(16)
        aes_context = Cipher(algorithms.AES(self.key), modes.CTR(self.IV), backend=default_backend())
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

manager = EncryptionManager()
mac = os.urandom(32)

email = input("Digite seu email: ")
senha = input("Digite sua senha: ")

plaintexts = [(email+"^"+senha).encode('utf-8')]

hmacCriado = hmac.HMAC(mac, hashes.SHA256(), backend=default_backend()) 
hmacCriado.update(plaintexts[0]) 
hmacSaida=hmacCriado.finalize()

ciphertexts = []

for m in plaintexts:
    ciphertexts.append(manager.updateEncryptor(m))
ciphertexts.append(manager.finalizeEncryptor())

print("----------------------------")
print("Sessions Keys: "+str(b64encode(manager.key+manager.IV+mac).decode('ascii')))
print("Cyphertext: "+str(b64encode(ciphertexts[0]).decode('ascii')))
print("HMAC: "+str(b64encode(hmacSaida).decode('ascii')))
print("----------------------------")

r = requests.post('http://localhost:5000/login', data={'session_keys': b64encode(manager.key+manager.IV+mac).decode('ascii'),'cyphertext': b64encode(ciphertexts[0]).decode('ascii'),'hmac': b64encode(hmacSaida).decode('ascii')},allow_redirects=False)
print(r.status_code)
r.cookies['session_id']
print("session_id: ",r.cookies['session_id'])
r = requests.get('http://localhost:5000/home', cookies={'session_id': r.cookies['session_id']})
print(r.status_code)