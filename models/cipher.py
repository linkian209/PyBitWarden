"""models.cipher

This module contains the ciphers that are stored in the database
"""
import json

from app import db
from models import funcs
from sqlalchemy import sql


class Cipher(db.Model):
    """
    The Cipher class stores the cipher string for an individual site's info.

    This also contains an enumeration of the different types of cipher

    Attributes:
        id (int): The id of this cipher
        user_id (Foreign Key): The user associated with this cipher
        folder_id (Foreign Key): The folder that contains this cipher
        organization_id (str): ID of the organization this is associated with
        cipher_type (int): The type of cipher
        favorite (bool): If this cipher is a favorite or not
        data (str): JSON serialized data contained in this cipher
        fields (str): JSON serialized fields contained in this cipher
        name (str): JSON serialized name of cipher
        notes (str): JSON serialized note on cipher
        login (str): JSON serialized login
        secure_note (str): JSON serialized secure note
        card (str): JSON serialized card
        identity (str): JSON serialized identity
        attachments (str): JSON serialized attachments
        create_date (DateTime): The creation time of this cipher
        update_date (DateTime): The time of the last update to this cipher
    """
    # Type enumeration
    TYPE_LOGIN = 1
    TYPE_NOTE = 2
    TYPE_CARD = 3
    TYPE_IDENTITY = 4

    # Member variables
    id = db.Column(
        db.String(64), name='id', primary_key=True,
        default=funcs.generateSecureUUID
    )
    user_id = db.Column(
        db.String(64), db.ForeignKey('user.id', ondelete='CASCADE')
    )
    folder_id = db.Column(
        db.String(64), db.ForeignKey('folder.id', ondelete='CASCADE'),
        nullable=True
    )
    organization_id = db.Column(db.String(64), nullable=True)
    cipher_type = db.Column(db.Integer, nullable=False)
    favorite = db.Column(db.Boolean(), default=False, nullable=False)
    data = db.Column(db.JSON(), nullable=True)
    name = db.Column(db.JSON(), nullable=True)
    notes = db.Column(db.JSON(), nullable=True)
    fields = db.Column(db.JSON(), nullable=True)
    login = db.Column(db.JSON(), nullable=True)
    secure_note = db.Column(db.JSON(), nullable=True)
    card = db.Column(db.JSON(), nullable=True)
    identity = db.Column(db.JSON(), nullable=True)
    attachments = db.Column(db.JSON(), nullable=True)
    create_date = db.Column(db.DateTime(), server_default=sql.func.now())
    update_date = db.Column(
        db.DateTime(), server_default=sql.func.now(), onupdate=sql.func.now()
    )

    # Functions
    def type_str(in_type):
        """
        Returns a string representation of the inputted type

        Args:
            :param in_type: The inputed type

        Returns:
            str: The string representation
        """
        if(in_type is Cipher.TYPE_LOGIN):
            return 'login'
        elif(in_type is Cipher.TYPE_NOTE):
            return 'note'
        elif(in_type is Cipher.TYPE_CARD):
            return 'card'
        elif(in_type is Cipher.TYPE_IDENTITY):
            return 'identity'
        else:
            return str(in_type)

    def updateFromParams(self, params):
        """
        This function will update a cipher based on the passed in parameters

        Args:
            :param self: This object
            :param params: A dictionary of params
        """
        self.folder_id = params['folderid']
        self.organization_id = params['organizationid']
        self.favorite = bool(params['favorite'])
        self.type = int(params['type'])
        self.name = params['name']
        self.notes = params['notes']
        self.fields = funcs.uppercaseFirstHash(params['fields'])

        # Parse additional data based on cipher type
        if(self.cipher_type is Cipher.TYPE_LOGIN):
            login_data = funcs.uppercaseFirstHash(params['login'])

            if(login_data['Uris'] and isinstance(login_data['Uris'], dict)):
                login_data['Uris'] = funcs.uppercaseFirstHash(
                    login_data['Uris']
                )

            self.login = login_data
        elif(self.cipher_type is Cipher.TYPE_NOTE):
            self.secure_note = funcs.uppercaseFirstHash(params['securenote'])
        elif(self.cipher_type is Cipher.TYPE_CARD):
            self.card = funcs.uppercaseFirstHash(params['card'])
        else:
            # TODO: Implement more types
            if(self.cipher_type is Cipher.TYPE_IDENTITY):
                self.identity = funcs.uppercaseFirstHash(params['identity'])

    def toHash(self):
        """
        Returns the cipher as a hash.

        Args:
            :param self: The object

        Returns:
            dict: The hash representation of the object
        """
        return {
            'Id': self.id,
            'Type': self.cipher_type,
            'RevisionDate': self.update_date.strftime(
                '%Y-%m-%dT%H:%M:%S.000000Z'
            ),
            'FolderId': self.folder_id,
            'Favorite': self.favorite,
            'OrganizationId': self.organization_id,
            'Attachments': self.attachments,
            'OrganizationUserTotp': False,
            'Object': 'cipher',
            'Name': self.name,
            'Notes': self.notes,
            'Fields': self.fields,
            'Login': self.login,
            'Card': self.card,
            'Identity': self.identity,
            'SecureNote': self.secure_note
        }

    def migrateData(self):
        """
        This function will migrate data from being an all in one and split it
        into separate fields.

        If there is no data, we will just return false. If the data is not able
        to be turned into a JSON, we will raise a ValueError. If the data is
        not a dict or a string, we will raise a TypeError.

        Args:
            :param self: The object

        Raises:
            TypeError: If this object's data is not a dict or string
            ValueError: If this object can not become a JSON
            NotImplementedError: If we try to migrate from a nonsupported type
        """
        if(self.data is None):
            return False

        if(isinstance(self.data, str)):
            try:
                data = json.loads(self.data)
            except(Exception):
                raise ValueError
        elif(isinstance(self.data, dict)):
            data = self.data
        else:
            raise TypeError

        self.name = data['Name']
        del data['Name']
        self.notes = data['Notes']
        del data['Notes']
        self.fields = data['Fields']
        del data['Fields']

        if(self.cipher_type is self.TYPE_LOGIN):
            data['Uris'] = {
                'Uri': data['Uri'],
                'Match': None
            }
            del data['Uri']
            self.login = data
        elif(self.cipher_type is self.TYPE_NOTE):
            self.secure_note = data
        elif(self.cipher_type is self.TYPE_CARD):
            self.card = data
        elif(self.cipher_type is self.TYPE_IDENTITY):
            self.identity = data
        else:
            raise NotImplementedError
