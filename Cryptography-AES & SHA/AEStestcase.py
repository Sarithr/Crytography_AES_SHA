import unittest, logging
from PythonAES import CryptographyAES
import socket

class AesTestCase(unittest.TestCase):
	def setup(self):
		logging.basicConfig(level = logging.DEBUG)
		socket.getaddrinfo('localhost', 8080)

	def testCryptography(self):
		aesObject = CryptographyAES()
		self.encryptCipher_text, self.encryptSalt, self.decryptCipher_text, self.decryptSalt, encrypted, isEncrypted, responseMessage = aesObject.main("sumathi")
		if (self.encryptCipher_text == self.decryptCipher_text):
			if (self.encryptSalt == self.decryptSalt):
				self.assertTrue(isEncrypted)
				self.assertEquals(responseMessage, "Password Encrypted")

	def testCryptographyDataWithCiphertext(self):
		aesObject = CryptographyAES()
		self.encryptCipher_text, self.encryptSalt, self.decryptCipher_text, self.decryptSalt, encrypted, isEncrypted, responseMessage = aesObject.main("sumathi")
		if (self.encryptCipher_text != self.decryptCipher_text):
			if (self.encryptSalt == self.decryptSalt):	
				self.assertFalse(isEncrypted)
				self.assertEquals(responseMessage, "Provide valid password to encrypt and decrypt")

	def testCryptographyDataWithSalt(self):			
		aesObject = CryptographyAES()
		self.encryptCipher_text, self.encryptSalt, self.decryptCipher_text, self.decryptSalt, encrypted, isEncrypted, responseMessage = aesObject.main("sumathi")
		if (self.encryptCipher_text == self.decryptCipher_text):
			if (self.encryptSalt != self.decryptSalt):	
				self.assertFalse(isEncrypted)
				self.assertEquals(responseMessage, "Provide valid password to encrypt and decrypt")
