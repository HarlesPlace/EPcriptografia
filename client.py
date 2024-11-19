from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes,hmac,serialization
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os, requests

class EncryptionManager:
    def __init__(self,recv_public_key):
        self.key = os.urandom(32)
        self.IV = os.urandom(16)
        with open(recv_public_key, "rb") as public_key_file_object:
            self.recv_public_key = serialization.load_pem_public_key(public_key_file_object.read(),backend=default_backend())
        aes_context = Cipher(algorithms.AES(self.key), modes.CTR(self.IV), backend=default_backend())
        self.encryptor = aes_context.encryptor()
    
    def updateEncryptorAES(self, plaintext):
        return self.encryptor.update(plaintext)
    
    def finalizeEncryptorAES(self):
        return self.encryptor.finalize()
    
    def EncryptorRSA(self, plaintext):
        ciphertext = self.recv_public_key.encrypt(plaintext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))
        return ciphertext

serverPublic_Key = input("Digite o nome do arquivo da Chave Publica do servidor: ")
manager = EncryptionManager(serverPublic_Key)
mac = os.urandom(32)

email = input("Digite seu email: ")
senha = input("Digite sua senha: ")
   
plaintexts = [(email+"^"+senha).encode('utf-8')]

sessionkeysCriptografadas=manager.EncryptorRSA(manager.key+manager.IV+mac)

hmacCriado = hmac.HMAC(mac, hashes.SHA256(), backend=default_backend()) 
hmacCriado.update(sessionkeysCriptografadas+plaintexts[0]) 
hmacSaida=hmacCriado.finalize()

ciphertexts = []

for m in plaintexts:
    ciphertexts.append(manager.updateEncryptorAES(m))
ciphertexts.append(manager.finalizeEncryptorAES())

print("----------------------------")
print("Sessions Keys: "+str(b64encode(sessionkeysCriptografadas).decode('ascii')))
print("Cyphertext: "+str(b64encode(ciphertexts[0]).decode('ascii')))
print("HMAC: "+str(b64encode(hmacSaida).decode('ascii')))
print("----------------------------")

r = requests.post('http://localhost:5000/login', data={'session_keys': b64encode(sessionkeysCriptografadas).decode('ascii'),'cyphertext': b64encode(ciphertexts[0]).decode('ascii'),'hmac': b64encode(hmacSaida).decode('ascii')},allow_redirects=False)
print("Código de resposta: ",r.status_code)
r.cookies['session_id']
print("session_id: ",r.cookies['session_id'])
r = requests.get('http://localhost:5000/home', cookies={'session_id': r.cookies['session_id']})
print("Código de resposta: ",r.status_code)