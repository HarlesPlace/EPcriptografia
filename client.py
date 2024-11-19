from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes,hmac,serialization
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric import padding
import os, requests
from cryptography import x509
from cryptography.x509.oid import NameOID

ca_root_cert_pem = b'''-----BEGIN CERTIFICATE-----
MIIDwTCCAqkCFHwleqTDe5jTkGnrjg2yZgra0bpxMA0GCSqGSIb3DQEBCwUAMIGc
MQswCQYDVQQGEwJCUjESMBAGA1UECAwJU0FPIFBBVUxPMRIwEAYDVQQHDAlTQU8g
UEFVTE8xDjAMBgNVBAoMBUVQVVNQMQwwCgYDVQQLDANQTVIxFTATBgNVBAMMDFBN
UjM0MTIgUm9vdDEwMC4GCSqGSIb3DQEJARYhcG1yMzQxMlJlZGVzSW5kdXN0cmlh
aXNAZ21haWwuY29tMB4XDTIyMTEyNDE3NDI1OVoXDTMyMTEyMTE3NDI1OVowgZwx
CzAJBgNVBAYTAkJSMRIwEAYDVQQIDAlTQU8gUEFVTE8xEjAQBgNVBAcMCVNBTyBQ
QVVMTzEOMAwGA1UECgwFRVBVU1AxDDAKBgNVBAsMA1BNUjEVMBMGA1UEAwwMUE1S
MzQxMiBSb290MTAwLgYJKoZIhvcNAQkBFiFwbXIzNDEyUmVkZXNJbmR1c3RyaWFp
c0BnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJp20x
yxCAfPsAfop68ZZQGerbrBgYpcMf+cl8RrTmnN79kajsdDmwtcCj2Vr6wDyBub3N
nVX08EiHbcq5G6r6O65BtcA+Lq+5yRz57s5SeT8TrxwcX/BZmkIBgbS7jL/q/CDS
fUWAyPjnZqQz3dTddwuAj06J8Ree8WFfqli10TuFrM081KgEEPsc65luGKN9+zq4
zCgCrtae5bmcBimdc0AkILkgtoes6NeChKe68YnDrhi7rPfSS7HnwVd0aDskixnR
7PGv5VwA11orDc2NxIH8DhF756pEY5LFtqZqYp1yZYcxhYrRnXvuOyzQ4dGT/RCZ
WYAHMajBOUbQmtEnAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAG5nVbC+afUl/48i
3QC+oBvs32Um2c2GeKNA+T5P2ufDxnXQurpPXCVwaCWoaBdFPpNqJNqCaNrTjVM5
+bZCJf+FBCkLj0iv2QQSDduEwtpUj+vj2l4+JfeEglSfSddsSHw3R/4CJD5EWznf
TDyhCvWRLDL+bZRQw3lU/B2j11RVDfJazVdFwkBrWeh2x7RWprfjwufSRwNYdjdv
ve0M8EGVZQNA11as6i3EsmgkMm7Vr6OU24ZkeSFDTHxlqVZ8Ona593KE2VNNfMv+
iJtJtBwotgRMfvdM9PcI6bpSkDjJmfSv6LOi74FDrpu8eefDf+EPLK2xO3lU++rn
tqvqn1o=
-----END CERTIFICATE-----
'''
NUSP='11807261'

class EncryptionManager:
    def __init__(self,recv_public_key):
        self.key = os.urandom(32)
        self.IV = os.urandom(16)
        self.recv_public_key = serialization.load_pem_public_key(recv_public_key,backend=default_backend())
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

certValidation=False

r = requests.get('http://localhost:5000/certificado')
if r.status_code==200:
    try:
        certRecebido = r.content
        print("Certificado recebido: ",certRecebido)
    except:
        print("Erro no recebimento do certificado")
    certServidor = x509.load_pem_x509_certificate(certRecebido, default_backend())
    certRoot = x509.load_pem_x509_certificate(ca_root_cert_pem, default_backend())
    if certServidor.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value==NUSP:
        if certServidor.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == certRoot.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
            try:
                certRoot.public_key().verify(certServidor.signature,certServidor.tbs_certificate_bytes,padding.PKCS1v15(),certServidor.signature_hash_algorithm)
                serverPublic_Key=certServidor.public_key()
                certValidation=True
            except Exception as e:
                print("Erro na validação do certificado! ",e)
        else:
            print("CN do emissor DIFERENTE ao CN do requerente do certificado raiz")      
    else:
        print("CN do requerente diferente de ",NUSP)

if certValidation:
    #serverPublic_Key = input("Digite o nome do arquivo da Chave Publica do servidor: ")
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