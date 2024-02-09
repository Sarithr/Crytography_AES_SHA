import unittest, logging
from PythonSHA import CryptographySHA
import socket
import bcrypt

class ShaTestCase(unittest.TestCase):
	def setup(self):
		logging.basicConfig(level = logging.DEBUG)
		socket.getaddrinfo('localhost', 8080)

	def testEncrypt(self):
		shaObject = CryptographySHA()
		hashed, encryptHashed, isDataEncrypted, responseMessage = shaObject.encrypt(b"susma")
		if (hashed == encryptHashed):	
			self.assertTrue(isDataEncrypted)
			self.assertEquals(responseMessage, "Data Encrypted Successfully")

	def testEncryptData(self):
		shaObject = CryptographySHA()
		hashed, encryptHashed, isDataEncrypted, responseMessage = shaObject.encrypt(b"susma")
		if (hashed != encryptHashed):
			self.assertFalse(isDataEncrypted)
			self.assertEquals(responseMessage, "Provide valid data to encrypt")

