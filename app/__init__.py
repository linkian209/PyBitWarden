"""app

This module contains all of the configuration for the start up of the Flask
application.

Attributes:
    app (Flask): The Flask application
    db (SQLAlchemy): Database object
"""
import sys

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from app import funcs

app = Flask(__name__)

# Get config based on Flask environment
if(app.config['ENV'] == 'development'):
    app.config.from_object('app.config.DevelopmentConfig')
elif(app.config['ENV'] == 'testing'):
    app.config.from_object('app.config.TestingConfig')
else:
    # Production config. Make sure environment variables exist
    if(funcs.mysqlEnvSet()):
        app.config.from_object('app.config.ProductionConfig')
    else:
        print(' ! Missing MySQL Environment Config! Exiting...')
        sys.exit()

db = SQLAlchemy()
