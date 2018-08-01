"""models.folder

This module contains the Folder Model.
"""
from app import db
from models import funcs
from sqlalchemy import sql


class Folder(db.Model):
    """
    Folder Model. Used to group various Ciphers together.

    Attributes:
        id (int): Folder ID
        name (str): Name of folder
        user_id (Foreign Key): User who owns this folder
        folder_id (Foreign Key): Parent folder of this folder
        create_date (DateTime): Creation time of folder
        update_date (DateTime): Time of last update
        ciphers (Relationship): List of all ciphers contained in this folder
        folders (Relationship): All sub folders of this folder

    Args:
        :param db.Model: SQLAlchemy Model
    """
    # Member Variables
    id = db.Column(
        db.String(64), name='id', primary_key=True,
        default=funcs.generateSecureUUID
    )
    user_id = db.Column(
        db.String(64), db.ForeignKey('user.id', ondelete='CASCADE')
    )
    name = db.Column(db.String(128), nullable=False)
    folder_id = db.Column(
        db.String(64), db.ForeignKey('folder.id', ondelete='CASCADE')
    )
    create_date = db.Column(db.DateTime, server_default=sql.func.now())
    update_date = db.Column(
        db.DateTime, default=sql.func.now(),
        onupdate=sql.func.now()
    )
    ciphers = db.relationship(
        'Cipher', backref='folder', lazy=True, passive_deletes=True
    )
    folders = db.relationship(
        'Folder', backref='folder', lazy=True, passive_deletes=True
    )

    # Fuctions
    def __repr__(self):
        """
        Representation function

        Args:
            :param self: This Object

        Returns:
            str: The representation of this class
        """
        return '<Folder {}>'.format(self.id)

    def toHash(self):
        """
        Returns this object as a dictionary.

        Args:
            :param self: This Object

        Returns:
            dict: This object as a dictionary
        """
        return {
            'Id': self.id,
            'RevisionDate': self.update_date.strftime(
                '%Y-%m-%dT%H:%M:%S.000000Z'
            ),
            'Name': self.name,
            'Object': 'folder'
        }
