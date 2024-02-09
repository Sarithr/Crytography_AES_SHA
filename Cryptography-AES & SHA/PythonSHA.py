import bcrypt
import logging

logging.basicConfig(level = logging.DEBUG)

logging.info("Encryption and Decryption using Secure Hashing Algorithm")
class CryptographySHA:
	def encrypt(self, password):
		logging.info("SHA Encryption Process")
		isDataEncrypted = False
		responseMessage = ""
		try:
			self.password = password
			hashed = bcrypt.hashpw(self.password, bcrypt.gensalt())
			encryptHashed = bcrypt.hashpw(self.password, hashed)
			logging.debug(hashed)
			logging.debug("The secretest message here")
			logging.debug("Data Encrypted")
			isDataEncrypted = True
			responseMessage = "Data Encrypted Successfully"
		except:
			logging.exception("Unable to encrypt the data")
		return hashed, encryptHashed, isDataEncrypted, responseMessage			

	
