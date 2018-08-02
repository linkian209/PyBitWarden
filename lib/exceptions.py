"""lib.exceptions

This module contains all of the exceptions for PyBitWarden
"""


class InvalidMACException(Exception):
    """
    Invalid MAC Exception. Raised when the cipher string MAC does not match the
    calculated mac.

    Exception stores both the cipher MAC and the calculated MAC. Exception
    also can be used as a string with the str() method

    Attributes:
        cipher_mac (str): MAC from the cipher string
        calc_mac (str): MAC calculated from the initialization vector and the
        cipher text

    Args:
        :param Exception: Exception base class
    """
    def __init__(self, cipher_mac, calc_mac):
        """
        Initialization method for this exception

        Args:
            :param self: This object
            :param cipher_mac: The MAC from the cipher string
            :param calc_mac: The calculated MAC
        """
        self.cipher_mac = cipher_mac
        self.calc_mac = calc_mac

    def __str__(self):
        """
        String Representaion of Exception. Returns generic error message.

        Args:
            :param self: This object
        """
        return 'Cipher String MAC and Calculated MAC do not match!'


class InvalidCipherStringException(Exception):
    """
    Invalid Cipher String Exception. Raised when attempting to parse a
    cipher string that is not formatted correctly.

    Examples:
        The incorrect string can be obtained directly from the Execption:
            try:
                cipher = CipherString.parse(bad_cipher_string)
            except InvalidCipherStringExeception as e:
                print('Bad cipher string: {}'.format(e.cipher_string))

            $ Bad cipher string: {...}

        The class can also be cast to a string for a generic error message
            try:
                cipher = CipherString.parse(bad_cipher_string)
            except InvalidCipherStringExeception as e:
                print(str(e))

            $ Error parsing {...}. Invalid format.

    Attributes:
        cipher_string (str): The incorrectly formatted cipher string

    Args:
        :param Exception: Exception base class
    """
    def __init__(self, cipher_string):
        """
        Initialization of this exception. Class only contains the badly
        formatted cipher string

        Args:
            :param self: This object
            :param cipher_string: The incorrectly formatted cipher string
        """
        self.cipher_string = cipher_string

    def __str__(self):
        """
        Generic error message for this Exception

        Args:
            :param self: This object

        Returns:
            str: The error message
        """
        return 'Error parsing {}. Invalid format.'.format(self.cipher_string)
