"""models.funcs

This module contains helper functions for the Models of the app.
"""
import uuid

from Crypto import Random


def generateSecureUUID():
    """
    This function generates a secure UUID for whatever needs it

    Returns:
        uuid: The generated uuid
    """
    return str(uuid.UUID(bytes=Random.get_random_bytes(16)))


# https://security.stackexchange.com/questions/83660/simple-string-comparisons-not-secure-against-timing-attacks
def constantTimeCompare(val1, val2):
    """
    This function compares 2 values in constant time if they are the same
    length. It will return false immediately if they are not the same length.

    This function has a margin of error of around 6 microseconds

    Args:
        :param val1: The first value to compare
        :param val2: The second value to compare

    Returns:
        bool: True if the values are the same, false otherwise
    """
    if(len(val2) is not len(val1)):
        return False

    if(not isinstance(val1, bytes)):
        val1 = val1.encode()

    if(not isinstance(val2, bytes)):
        val2 = val2.encode()

    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y

    return result == 0


def uppercaseFirstHash(data):
    """
    This function takes the inputted data and formats all of the keys to be
    lowercase with the first letter capitalized. If the input is anything but a
    dictionary, it simply raises a TypeError.

    Args:
        :param data: The data to be reformatted

    Raises:
        TypeError when data is not a dict.

    Returns:
        dict: The reformatted dictionary
    """
    if(not isinstance(data, dict)):
        raise TypeError

    return {k.lower().capitalize(): v for k, v in data.items()}
