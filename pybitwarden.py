"""pybitwarden.py

This module is called by the flask application on start up. This should be set
with the FLASK_APP environment variable.

The app currently supports 3 environments:
    * production
    * development
    * testing
You can set one by using the FLASK_ENV environment variable

If running in production, also set the FLASK_MYSQL_USER and FLASK_MYSQL_PASS
environment variables

Example:
    $ set FLASK_APP=pybitwarden.py
    $ set FLASK_ENV=development
    $ flask run
"""
from app import app
from app import db
from app import routes # noqa
from models.user import User # noqa
from models.folder import Folder # noqa


db.init_app(app)
