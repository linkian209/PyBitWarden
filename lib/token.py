"""lib.token

This module contains the Token object. This is used to sign JSON payloads
"""
import os
import jwt

from app import app
from Crypto import PublicKey


class Token():
    """
    This class is used for the creation of login tokens

    Attributes:
        public_rsa (RsaKey): Public RSA string
        private_rsa (RsaKey): Private RSA String
        key_path (str): Absolute path to JWT key
    """
    def __init__(self, key_path=None):
        """
        Initializes Token object. If no RSA key exists, it creates one then
        saves it off.

        Args:
            :param key: Path for RSA key, if no keypath is passed in, use
            the application default one
        """
        self.key_path = key_path

        if(self.key_path is None):
            self.key_path = app.config['JWT_KEY_PATH']

        if(os.path.exists(self.key_path)):
            with open(self.key_path, 'r') as f:
                self.private_rsa = PublicKey.RSA.import_key(f.read())
                self.public_rsa = self.private_rsa.publickey()
        else:
            os.makedirs(self.key_path, exists_ok=True)
            with open(self.key_path, 'w') as f:
                self.private_rsa = PublicKey.RSA.generate(2048)
                self.public_rsa = self.private_rsa.publickey()
                print(self.private_rsa.export_key('PEM').decode(), file=f)

    def sign(self, payload):
        """
        Encodes a payload using the private key

        Args:
            :param self: This object
            :param payload: payload to encode

        Returns:
            str: Encoded payload
        """
        return jwt.encode(payload, self.private_key.export_key('PEM'), 'RS256')
