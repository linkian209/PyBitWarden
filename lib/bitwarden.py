"""lib.bitwarden

This module contains all of the magic that the Bitwarden algorithms use. This
will be used to test behaviors as well as create new ciphers.
"""
import base64

from Crypto import Hash, Random
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Protocol import KDF
from .cipherstring import CipherString
from .exceptions import InvalidMACException


class Bitwarden():
    """
    Bitwarden class. This contains functions to replicate the way the client
    apps work.
    """
    def makeKey(password, salt):
        """
        Makes a key using the inputed password and salt

        Args:
            :param password: Password to hash
            :param salt: Salt used for hash

        Returns:
            bytes: The hashed password.
        """
        return KDF.PBKDF2(
            password, salt, dkLen=32, count=5000, hmac_hash_module=Hash.SHA256
        )

    def makeEncryptionKey(key):
        """
        Makes an encryption key using the inputted key and random bytes.

        Args:
            :param key: The key to use for encrpytion

        Returns:
            str: The encryption key
        """
        init_vector = Random.get_random_bytes(16)

        rand_bytes = Padding.pad(Random.get_random_bytes(64), AES.block_size)

        if(not isinstance(key, bytes)):
            key = key.encode()

        cipher = AES.new(key, AES.MODE_CBC, iv=init_vector)

        cipher_text = cipher.encrypt(rand_bytes)
        return str(CipherString(
            CipherString.TYPE_AESCBC256_B64, base64.b64encode(init_vector),
            base64.b64encode(cipher_text)
        ))

    def hashPassword(password, salt):
        """
        Encode a password for use in login or signup

        Args:
            :param password: User's password
            :param salt: Salt for the hashing

        Returns:
            str: The hashed password
        """
        key = Bitwarden.makeKey(password, salt)

        return KDF.PBKDF2(
            key, password, count=5000, dkLen=32, hmac_hash_module=Hash.SHA256
        )

    def encrypt(plain_text, key, mac_key=None):
        """
        Encrypt inputted plain text using the key and return a CipherString.

        Args:
            :param plain_text: Plain text to be encoded
            :param key: Encryption Key
            :param macKey: (Default = None) Addition MAC Key for encryption

        Returns:
            CipherString: Encrypted plain text as a CipherString object
        """
        init_vector = Random.get_random_bytes(16)

        # We must pad plain text to match the initialization vector
        if(not isinstance(plain_text, bytes)):
            plain_text = plain_text.encode()

        plain_text = Padding.pad(plain_text, AES.block_size)

        cipher = AES.new(key, AES.MODE_CBC, iv=init_vector)
        cipher_text = cipher.encrypt(plain_text)

        mac = None
        cipher_type = CipherString.TYPE_AESCBC256_B64

        if(mac_key is not None):
            mac = Hash.HMAC.new(
                mac_key,
                init_vector + cipher_text,
                digestmod=Hash.SHA256
            ).digest()
            mac = base64.b64encode(mac)
            cipher_type = CipherString.TYPE_AESCBC256_HMACSHA256_B64

        return str(CipherString(
            cipher_type, base64.b64encode(init_vector),
            base64.b64encode(cipher_text), mac=mac
        ))

    def doubleHMACVerify(mac_key, mac1, mac2):
        """
        Perform Double HMAC Verification

        Args:
            :param mac_key: MAC Key
            :param mac1: MAC 1
            :param mac2: Mac 2

        Returns:
            bool: Returns true if the MACs are equal. False otherwise
        """
        digested_mac1 = Hash.HMAC.new(mac_key, msg=mac1, digestmod=Hash.SHA256)
        digested_mac2 = Hash.HMAC.new(mac_key, msg=mac2, digestmod=Hash.SHA256)

        return digested_mac1.digest() == digested_mac2.digest()

    def decrypt(input_cipher_string, key, mac_key=None):
        """
        Decrypt the inputted cipher text based on the encryption type.
        Decrypted plain text will be unpadded before it is returned.

        Args:
            :param input_cipher_string: Cipher text to decrypt
            :param key: Decryption key
            :param mac_key: (Default = None) MAC key for MAC verification

        Raises:
            InvalidMACException: If the cipher string MAC and the calculated
            MAC do not match, this exception will be raised

        Returns:
            bytes: Decrypted plain text in a bytes string
        """
        cipher_string = CipherString.parseString(input_cipher_string)
        init_vector = base64.b64decode(cipher_string.init_vector)
        cipher_text = base64.b64decode(cipher_string.cipher_text)

        mac = None
        if(cipher_string.mac is not None):
            mac = base64.b64decode(cipher_string.mac)

        # AES-CBC-256
        if(cipher_string.type is CipherString.TYPE_AESCBC256_B64):
            cipher = AES.new(key, AES.MODE_CBC, iv=init_vector)
            plain_text = cipher.decrypt(cipher_text)

            plain_text = Padding.unpad(
                plain_text, AES.block_size
            )

        # AES-CBC-256 + HMAC-SHA256
        elif(cipher_string.type is CipherString.TYPE_AESCBC256_HMACSHA256_B64):
            # Verify HMAC first
            calc_mac = Hash.HMAC.new(
                mac_key, msg=(init_vector + cipher_text),
                digestmod=Hash.SHA256
            ).digest()

            if(not Bitwarden.doubleHMACVerify(mac_key, mac, calc_mac)):
                # These MACs are not the same
                raise InvalidMACException(mac, calc_mac)

            # Now decrypt cipher text
            cipher = AES.new(key, AES.MODE_CBC, iv=init_vector)
            plain_text = cipher.decrypt(cipher_text)

            plain_text = Padding.unpad(
                plain_text, AES.block_size
            )

        # Other Cipher Types
        else:
            # TODO: Implement other cipher types
            plain_text = cipher_string

        return plain_text
