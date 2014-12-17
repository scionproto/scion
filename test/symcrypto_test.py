from lib.crypto.symcrypto import *

import unittest
import logging

class TestSymcrypto(unittest.TestCase):
    """
    Unit tests for Symmetric Cryptography.
    """

    def test(self):
        """
	Symmetric cryptography test case. Test includes
	1. Hash (sha3) hash testing. Compare generated results with http://sha3calculator.appspot.com/
	2. MAC (AES-MAC) testing for random symmetric keys and messages.
	3. Block cipher (AES-GCM) testing with random keys and messages.
        """
        print ("-------------------------------------Hash Testing-------------------------------------")
        msg = 'sadjlaskdlaksdmlamczVRJ8JiM0J4M4ioyLJM6qR1CznEMYnymr1jJxgcLATjlEOFMc6x02wpRCUjo'
        print ("msg = ", msg)
        print ("sha3-224 digest = ", Hash(msg, 'SHA3-224'))
        print ("sha3-256 digest = ", Hash(msg, 'SHA3-256'))
        print ("sha3-384 digest = ", Hash(msg, 'SHA3-384'))
        print ("sha3-512 digest = ", Hash(msg, 'SHA3-512'))
        
        print ("-------------------------------------MAC Testing-------------------------------------")
        key = GenRandomByte(16)
        engine = MACObject(key)
        print ("key = ", key)
        msg1 = encode(GenRandomByte(20), 'hex').decode('utf-8')
        print ("msg1 = ", msg1)
        mac1 = MACCompute(engine, msg1)
        print ("MACCompute(msg1) = ", mac1)
        msg2 = encode(GenRandomByte(20), 'hex').decode('utf-8')
        print ("msg2 = ", msg2)
        mac2 = MACCompute(engine, msg2)
        print ("MACCompute(msg) = ", mac2)
        print ("MACverify(msg) = ", MACVerify(engine, msg2, mac2))
        
        print ("-------------------------------------Block Cipher Testing-------------------------------------")
        key = GenRandomByte(16)
        iv = GenRandomByte(16)
        msg = 'This is a message to be protected'
        auth = binascii.unhexlify('D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001')
        print ('key = ', key, 'iv = ', iv, 'auth', auth)
        print ('Message = ', msg)
        AuthCipher = AuthenEncrypt(key, msg.encode('utf-8'), iv, auth)
        print ('Cipher = ', AuthCipher)
        deCipher = AuthenDecrypt(key, AuthCipher, iv, auth)
        print ('deCipher = ', deCipher.decode('utf-8'))
        
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
