"""models.user

This Module contains the User Model
"""
import pyotp

from app import db
from models import funcs


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
    id = db.Column(
        db.String(64), name='id', primary_key=True,
        default=funcs.generateSecureUUID
    )
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False)
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

    def __repr__(self):
        """
        Representation of this object as a string
            :param self: This object
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
