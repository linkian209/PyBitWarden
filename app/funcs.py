"""app.funcs

This module contains helper functions for the flask app.

"""
import os


def mysqlEnvSet():
    """
    This functions checks to ensure that the MySQL username and password
    are in environment variables so the production application can start up.

    Returns:
        bool: the return value. Returns true if both the username and password
        are both in environment variables. False otherwise.
    """
    if(os.environ.get('FLASK_MYSQL_USER')):
        if(os.environ.get('FLASK_MYSQL_PASS')):
            return True

    return False
