"""models.user

This Module contains the User Model
"""
import pyotp

from app import db
from models import funcs
from lib.bitwarden import Bitwarden


class User(db.Model):
    """
    This model is used to store users.

    Attributes:
        id (int): User ID
        name (str): User's Name
        email (str): User's Email
        email_verified (bool): User's Email is verified
        premium (bool): User's Premium Status
        master_password_hint (str): Master Password Hint
        culture (str): Language/Country string
        totp_secret (str): Two Factor Authentication secret key
        two_factor_enabled (bool): User has Two Factor Authentication Enabled
        key (str): User's encryption key
        security_stamp (str): Security Stamp
        folders (relationship): Folders owned by user
        cipers (relationship): Ciphers owned by user
        devices (relationship): Devices owned by user

    Args:
        :param db.Model: The Model Base Class
    """
    # Member Variables
    id = db.Column(
        db.String(64), name='id', primary_key=True,
        default=funcs.generateSecureUUID
    )
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    password_hash = db.Column(db.string(128), nullable=False)
    email_verified = db.Column(
        db.Boolean, nullable=False, default=False
    )
    premium = db.Column(
        db.Boolean, nullable=False, default=False
    )
    master_password_hint = db.Column(db.Text, nullable=True)
    culture = db.Column(
        db.String(64), nullable=False, default='en-US'
    )
    totp_secret = db.Column(db.String(256), nullable=True)
    two_factor_enabled = db.Column(
        db.Boolean, nullable=False, default=False
    )
    key = db.Column(db.String(256), nullable=False)
    security_stamp = db.Column(
        db.String(64), nullable=False,
        default=funcs.generateSecureUUID
    )
    folders = db.relationship(
        'Folder', backref='user', lazy=True, passive_deletes=True
    )
    ciphers = db.relationship(
        'Cipher', backref='user', lazy=True, passive_deletes=True
    )
    devices = db.relationship(
        'Device', backref='user', lazy=True, passive_deletes=True
    )

    # Functions
    def __repr__(self):
        """
        Representation of this object as a string

        Args:
            :param self: This object

        Returns:
            str: String representation of object
        """
        return '<User {}>'.format(self.name)

    def toHash(self):
        """
        Returns this object as a dict

        Args:
            :param self: This object

        Returns:
            dict: This object as a dict
        """
        return {
            'Id': self.id,
            'Name': self.name,
            'Email': self.email,
            'EmailVerified': self.email_verified,
            'Premium': self.premium,
            'MasterPasswordHint': self.master_password_hint,
            'Culture': self.culture,
            'TwoFactorEnabled': self.two_factor_enabled,
            'Key': self.key,
            'PrivateKey': None,
            'SecurityStamp': self.security_stamp,
            'Organizations': [],
            'Object': 'profile'
        }

    def verifyOTP(self, code):
        """
        Verify the passed in code against the user's current OTP.

        Args:
            :param1 self: This object
            :param2 code: The passed in OTP

        Returns:
            bool: True if the codes match, false otherwise.
        """
        if(pyotp.TOTP(self.totp_secret).now() == code):
            return True

        return False

    def decryptDataUsingMasterKey(self, data, master_key):
        """
        The user model contains an encrypted version of its encryption key.
        First, decrypt the master key then decrypt the data.

        Args:
            :param self: This user
            :param data: The cipher string that needs decrypted
            :param master_key: The master password used to decrypt the
            encryption key

        Returns:
            bytes: The decrypted plain text as a byte string
        """
        enc_key = Bitwarden.decrypt(
            self.key.encode(), master_key[:32], mac_key=master_key[32:64]
        )
        return Bitwarden.decrypt(
            data, enc_key[:32], mac_key=enc_key[32:64]
        )

    def encryptDataUsingMasterKey(self, data, master_key):
        """
        The user model contains an encrypted version of the encryption key.
        First decrypt that key then encrypt the data

        Args:
            :param self: This user
            :param data: The plain text to be encrypted
            :param master_key: The master key

        Returns:
            str: The encrypted cipher string
        """
        enc_key = Bitwarden.decrypt(
            self.key.encode(), master_key[:32], mac_key=master_key[32:64]
        )
        return Bitwarden.encrypt(
            data, enc_key[:32], mac_key=enc_key[32:64]
        )

    def comparePasswordHash(self, hash):
        """
        Compares if the user's password hash matches the inputed one

        Args:
            :param self: The user
            :param hash: The hash to compare against

        Returns:
            bool: True if the hashes are the same, false otherwise.
        """
        return funcs.constantTimeCompare(self.password_hash, hash)

    def updateMasterKey(self, old_password, new_password):
        """
        This function updates the master key for the random encryption key. We
        want to preserve this random encryption key. So we will decrypt with
        the old key, then recrypt with the new key.

        Args:
            :param self: This user
            :param old_password: The old master password
            :param new_password: The new master password
        """
        enc_key = Bitwarden.decrypt(
            self.key, Bitwarden.makeKey(old_password, self.email), None
        )
        self.key = Bitwarden.encrypt(
            enc_key, Bitwarden.makeKey(new_password, self.email)
        )

        self.password_hash = Bitwarden.hashPassword(new_password, self.email)
        self.security_stamp = funcs.generateSecureUUID()
