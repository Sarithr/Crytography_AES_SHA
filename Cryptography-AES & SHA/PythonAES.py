import hashlib
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode
import os
from Cryptodome.Random import get_random_bytes
import logging

logging.basicConfig(level = logging.DEBUG)

logging.info("Encryption and Decryption using Advanced Encryption Standard")
class CryptographyAES:
    def encrypt(self, plain_text, password):
        try:
            logging.info("AES Encryption process")
            self.encryptSalt = get_random_bytes(AES.block_size)
            private_key = hashlib.scrypt(password.encode(), salt = self.encryptSalt, n = 2**14, r = 8, p = 1, dklen = 32)
            cipher_config = AES.new(private_key, AES.MODE_GCM)
            self.encryptCipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
            logging.debug(self.encryptCipher_text)
            logging.debug(self.encryptSalt)            
            logging.debug("Password Encrypted")
        except:
            logging.exception("Unable to encrpt the password")    
        return {
            'cipher_text': b64encode(self.encryptCipher_text).decode('utf-8'),
            'salt': b64encode(self.encryptSalt).decode('utf-8'),
            'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }

    def decrypt(self, enc_dict, password):
        try:
            logging.info("AES Decryption process")
            self.decryptSalt = b64decode(enc_dict['salt'])
            self.decryptCipher_text = b64decode(enc_dict['cipher_text'])
            nonce = b64decode(enc_dict['nonce'])
            tag = b64decode(enc_dict['tag'])
            private_key = hashlib.scrypt(password.encode(), salt = self.decryptSalt, n = 2**14, r = 8, p = 1, dklen = 32)
            cipher = AES.new(private_key, AES.MODE_GCM, nonce = nonce)
            decrypted = cipher.decrypt_and_verify(self.decryptCipher_text, tag)
            logging.debug(self.decryptCipher_text)
            logging.debug(self.decryptSalt)
            logging.debug("Password Decrypted")
        except:    
            logging.exception("Unable to decrypt the password")   
        return decrypted

    def main(self, password):
        isEncrypted = False
        responseMessage = ""
        try:
            self.password = password
            encrypted = self.encrypt("The secretest message here", password)
            decrypted = self.decrypt(encrypted, password)
            logging.debug("Password Encrypted and Decrypted")
            logging.debug(self.encryptCipher_text)
            logging.debug(self.encryptSalt)
            logging.debug(self.decryptCipher_text)
            logging.debug(self.decryptSalt)
            isEncrypted = True
            responseMessage = "Password Encrypted"
        except:
            logging.exception("Unable to encrypt and decrypt the password")   
        return self.encryptCipher_text, self.encryptSalt, self.decryptCipher_text, self.decryptSalt, encrypted, isEncrypted, responseMessage     

aesObject = CryptographyAES()
aesObject.main("sumathi")