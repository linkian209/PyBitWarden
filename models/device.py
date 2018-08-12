"""models.device

This module contains the Device Model.

Attributes:
    DEFAULT_VALIDITY (int): The default number of seconds a token is valid for
"""
from app import db
from base64 import urlsafe_b64encode
from Crypto import Random
from models import funcs
from models.user import User
from lib.token import Token
from sqlalchemy import sql
from time import time


DEFAULT_VALIDITY = 3600


class Device(db.Model):
    """
    This model is used to store registered devices for users.

    Attributes:
        id (int): Device ID
        access_token (str): The devices access token
        refresh_token (str): The refresh token
        token_expires_at (date): The time when the token expires
        create_date (DateTime): Creation time of folder
        update_date (DateTime): Time of last update
        user_id (Foreign Key): The user associated with this device

    Args:
        :param db.Model: The Model base class
    """
    # Member variables
    id = db.Column(
        db.String(64), name='id', primary_key=True,
        default=funcs.generateSecureUUID
    )
    refresh_token = db.Column(
        db.String(64), nullable=True
    )
    access_token = db.Column(
        db.string(256), nullable=True
    )
    token_expires_at = db.Column(
        db.DateTime, nullable=True
    )
    user_id = db.Column(
        db.String(64), db.ForeignKey('user.id', ondelete='CASCADE')
    )
    create_date = db.Column(db.DateTime, server_default=sql.func.now())
    update_date = db.Column(
        db.DateTime, default=sql.func.now(),
        onupdate=sql.func.now()
    )

    # Functions
    def regenerateTokens(self, validity=DEFAULT_VALIDITY):
        """
        This function regenerates the tokens for the device.

        Args:
            :param self: This device
            :param validity: How long the will stay valid
        """
        if(self.refresh_token is None):
            self.refresh_token = urlsafe_b64encode(
                Random.get_random_bytes(64)
            ).decode()[:64]

        self.token_expires_at = validity

        user = User.query.get(self.user_id)

        self.access_token = Token().sign({
            'nbf': time() - 120,
            'exp': self.token_expires_at,
            'iss': '/identity',
            'sub': user.id,
            'premium': user.premium,
            'name': user.name,
            'email': user.email,
            'email_verified': user.email_verified,
            'sstamp': user.security_stamp,
            'device': self.id,
            'scope': ['api', 'offline_access'],
            'amr': ['Application']
        })
