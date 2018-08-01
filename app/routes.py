"""app.routes

This module contains all of the routes for PyBitWarden.

"""
from app import app


@app.route('/')
@app.route('/index')
def index():
    """
    '/' or '/index' endpoint. For testing.

    Todo:
        Remove this once app is complete.
    """
    return "Hello, World!"
