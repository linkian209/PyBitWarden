"""test.test_bitwarden.py

This module contains all of the tests for the Bitwarden class
"""
import pytest
import Crypto

from lib.bitwarden import Bitwarden
from lib.cipherstring import CipherString
from lib.exceptions import InvalidMACException


def testDoubleHMAC():
    """
    This test verifies that the double HMAC verification works correctly.

    mac_1 should equal itself.
    mac_2 should equal mac_3.
    mac_2 should not equal mac_4.
    """
    mac_key = b'test_key'
    mac_1 = Crypto.Hash.HMAC.new(
        mac_key, msg=b'test1', digestmod=Crypto.Hash.SHA256
    )
    mac_2 = Crypto.Hash.HMAC.new(
        mac_key, msg=b'test2', digestmod=Crypto.Hash.SHA256
    )
    mac_3 = Crypto.Hash.HMAC.new(
        mac_key, msg=b'test2', digestmod=Crypto.Hash.SHA256
    )
    mac_4 = Crypto.Hash.HMAC.new(
        mac_key, msg=b'test3', digestmod=Crypto.Hash.SHA256
    )

    assert Bitwarden.doubleHMACVerify(
        mac_key, mac_1.digest(), mac_1.digest()
    )
    assert Bitwarden.doubleHMACVerify(
        mac_key, mac_2.digest(), mac_3.digest()
    )
    assert not Bitwarden.doubleHMACVerify(
        mac_key, mac_2.digest(), mac_4.digest()
    )


def testMakeKey():
    """
    Verify that key creation is working.

    test_hash1 should not equal test_hash2.
    test_hash1 should equal real_hash1
    """
    test_password1 = 'password'
    test_password2 = 'passw0rd'
    test_salt = 'salt'
    real_hash = b'\x8f\xc2\xbc\xff\xbbK\x1a\xc9\xb9\xde\x03X\x8d9\x0f=\x9b\xf36\xc2\xc4B,\x90\xc1X\xccqB%\xf6)' # noqa

    test_hash1 = Bitwarden.makeKey(test_password1, test_salt)
    test_hash2 = Bitwarden.makeKey(test_password2, test_salt)

    assert test_hash1 == real_hash
    assert test_hash1 != test_hash2


def testMakeEncryptionKey():
    """
    Verify that unique encryption keys are generated, even if the keys
    are not unique.

    To test, we will make 100 encryption keys and store them in a list, then
    verify that none are unique by making them into a set and comparing the
    lengths of the list and set.
    """
    test_password = 'password'
    test_salt = 'salt'

    test_key = Bitwarden.makeKey(test_password, test_salt)
    test_keys = [Bitwarden.makeEncryptionKey(test_key) for x in range(100)]

    assert len(test_keys) is len(set(test_keys))


def testHashPassword():
    """
    Verify that password hashing works.

    test_hash1 should not equal test_hash2.
    test_hash1 should equal real_hash1
    """
    test_password1 = 'password'
    test_password2 = 'passw0rd'
    test_salt = 'salt'

    real_hash = b'\xa4\xe0%\xeb\xe5:\xd4E\xbd\x9e\x82\xd9a\xe1\xe9M\xc8L\x07h\xe2;\x8b\x80SM\x92\xb2\x12w\xeb\x81' # noqa
    test_hash1 = Bitwarden.hashPassword(test_password1, test_salt)
    test_hash2 = Bitwarden.hashPassword(test_password2, test_salt)

    assert test_hash1 == real_hash
    assert test_hash1 != test_hash2


def testEncryptDecrypt():
    """
    Verify that an encrypted plain text decrypts to the same text given the
    same key.
    """
    plain_text = 'This is a test'
    test_key = Bitwarden.makeKey('password', 'example@test.com')

    cipher_string = Bitwarden.encrypt(plain_text, test_key)

    assert plain_text == Bitwarden.decrypt(cipher_string, test_key).decode()
    assert plain_text == Bitwarden.decrypt(
        str(CipherString.parseString(cipher_string)), test_key
    ).decode()


def testEncryptDecryptMAC():
    """
    Verify that an encrypted plain text decrypts to the same text given the
    same key and MAC Key.

    plain_text should decrypt correctly using the same key and MAC key.
    decrypt should raise an exception when using a different MAC key.
    """
    plain_text = 'This is another test'
    input_key = Bitwarden.makeKey('password', 'example@test.com')
    encrypt_key = Bitwarden.makeEncryptionKey(input_key)
    whole_key = Bitwarden.decrypt(encrypt_key, input_key)
    test_key = whole_key[:32]
    mac_key1 = whole_key[32:64]
    mac_key2 = whole_key[:32]

    cipher_string = Bitwarden.encrypt(plain_text, test_key, mac_key1)

    assert plain_text == Bitwarden.decrypt(
        cipher_string, test_key, mac_key1
    ).decode()
    assert plain_text == Bitwarden.decrypt(
        str(CipherString.parseString(cipher_string)), test_key, mac_key1
    ).decode()

    with pytest.raises(InvalidMACException):
        Bitwarden.decrypt(cipher_string, test_key, mac_key2)
        Bitwarden.decrypt(
            str(CipherString.parseString(cipher_string)), test_key, mac_key2
        )
