"""app.config

This module contains the various configurations for PyBitWarden based on
the environment type.
"""
import os

from app import app


class Config(object):
    """
    Base Config class to be inherited by the other configs.

    Attributes:
        DEBUG (bool): Debugging to be defaulted to off
        TESTING (bool): Testing defaulted to off
        SQLALCHEMY_DATABASE_URL (str): Default Database URI (memory)

    Args:
        :param object: Flask app
    """
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    JWT_KEY_PATH = '{}/db/jwt.key'.format(app.instance_path)


class ProductionConfig(Config):
    """
    Production Configuration

    Attributes:
        SQLALCHEMY_DATABASE_URL (str): MySQL URL

    Args:
        :param Config: Base Config Object
    """
    SQLALCHEMY_DATABASE_URI = 'mysql://{}:{}@localhost/pybitwarden'.format(
        os.environ.get('FLASK_MYSQL_USER'),
        os.environ.get('FLASK_MYSQL_PASS')
    )


class DevelopmentConfig(Config):
    """
    Development Configuration

    Attributes:
        DEBUG (bool): Debugging is on

        SQLALCHEMY_TRACK_MODIFICATIONS (bool): In development, disable
        modification tracking

        SQLALCHEMY_DATABASE_URL (str): SQLITE3 URL

    Args:
        :param Config: Base Config Object
    """
    DEBUG = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/db/pybitwarden.db'.format(
        os.path.dirname(app.instance_path)
    )


class TestingConfig(Config):
    """
    Testing Configuration

    Attributes:
        TESTING (bool): Testing turned on

    Args:
        :param Config: Base Config Object
    """
    TESTING = True
