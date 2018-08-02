"""lib.cipherstring

This module contains the CipherString object as well as the exception it
throws on an invalid parse
"""
import re

from .exceptions import InvalidCipherStringException


class CipherString():
    """
    The Cipher String class. This class is used to work with the cipher
    strings.

    This class also as an enumeration of types to describe what type of
    CipherString that this is.

    Attributes:
        type (int): The type of Cipher String
        init_vector (bytes): base64 encoded bytes of the initialization vector
        cipher_text (bytes): base64 encoded bytes of the cipher text
        mac (byes): Message Authentication Code for cipher text
    """
    # Type Enumeration
    TYPE_AESCBC256_B64 = 0
    TYPE_AESCBC128_HMACSHA256_B64 = 1
    TYPE_AESCBC256_HMACSHA256_B64 = 2
    TYPE_RSA2048_OAEPSHA256_B64 = 3
    TYPE_RSA2048_OAEPSHA1_B64 = 4
    TYPE_RSA2048_OAEPSHA256_HMACSHA256_B64 = 5
    TYPE_RSA2048_OAEPSHA1_HMACSHA256_B64 = 6

    # Functions
    def __init__(self, type, init_vector, cipher_text, mac=None):
        """
        Initialization function for CipherString class. The MAC key is optional

        Example:
            $ str(CipherString(CipherString.TYPE_AESCBC256_B64, iv, ct))
            $ "0.uRcMe+Mc2nmOet4yWx9BwA==|PGQhpYUlTUq/vBEDj1KOHVMlTIH1eecMl0j80
               +Zu0VRVfFa7X/MWKdVM6OM/NfSZicFEwaLWqpyBlOrBXhR+trkX/dPRnfwJD2B93
               hnLNGQ="

        Args:
            :param self: This object
            :param type: The type of Cipher String
            :param init_vector: Initialization Vector for cipher text
            :param cipher_text: The cipher text
            :param mac: (Default = None) The MAC
        """
        self.type = type
        self.init_vector = init_vector
        self.cipher_text = cipher_text
        self.mac = mac

    def __str__(self):
        """
        This function returns the representation of this object as string.

        Args:
            :param self: This object

        Returns:
            str: The object as a string
        """
        retval = '{}.{}|{}'.format(
            self.type, self.init_vector.decode(), self.cipher_text.decode()
        )

        if(self.mac is not None):
            retval += '|{}'.format(self.mac.decode())

        return retval

    def parseString(cipher_string):
        """
        This function takes in a cipher string and returns a CipherString.

        Args:
            :param cipher_string: Cipher string to be parsed

        Raises:
            InvalidCipherStringException: This is raised if the inputted cipher
            string is not correctly formatted

        Returns:
            CipherString: Parsed cipher string as a CipherString object
        """
        pattern = re.compile('\A(\d)\.([^|]+)\|(.+)\Z')

        m = pattern.match(cipher_string)

        if(m is not None):
            cipher_text = None
            mac = None

            if(len(m.group(3).split('|')) is 1):
                cipher_text = m.group(3).encode()
            else:
                cipher_text, mac = [x.encode() for x in m.group(3).split('|')]

            return CipherString(
                int(m.group(1)), m.group(2).encode(), cipher_text, mac
            )

        else:
            raise InvalidCipherStringException(cipher_string)
