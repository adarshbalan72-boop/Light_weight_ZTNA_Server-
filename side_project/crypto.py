from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import os
import xml.etree.ElementTree as ET
import io

certificate=("server.key")
with open(certificate,"rb") as key_file:
    key = hashlib.sha256(key_file.read()).digest()

aes=AESGCM(key)

plain_config=("config")

def decypt_conf(enc_file):
    with open(enc_file,"rb") as data:
        encypt_data=data.read()

    nonce=os.encypt_data[:12]
    ciphertext = encypt_data[12:]

    plaintext=aes.decrypt(nonce,ciphertext,None)

    tree = ET.parse(io.BytesIO(plaintext))

    print("data decrypted")

def encryp_conf(tree,enc_file):
    xml_data=ET.tostring(tree.getroot(),encoding="utf-8",xml_declaration=True)
    nonce =os.urandom(12)
    
    ciphertext =aes.encrypt(nonce,xml_data,None)

    with open(enc_file,"wb") as enrypt_file:
        enrypt_file.write(nonce + ciphertext)

#https://www.qpython.com/python-how-to-encrypt-and-decrypt-with-aes-4h1k/



