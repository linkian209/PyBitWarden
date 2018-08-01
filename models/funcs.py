"""models.funcs

This module contains helper functions for the Models of the app
"""
import uuid

from OpenSSL import rand


def generateSecureUUID():
    """
    This function generates a secure UUID for whatever needs it

    Returns:
        uuid: The generated uuid
    """
    return str(uuid.UUID(bytes=rand.bytes(16)))
