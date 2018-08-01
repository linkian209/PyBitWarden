"""app.routes

This module contains all of the routes for PyBitWarden.

"""
from app import app
from flask import jsonify


@app.route('/')
@app.route('/index')
def index():
    """
    '/' or '/index' endpoint. For testing.

    Returns:
        Flask.Response: A test response

    Todo:
        Remove this once app is complete.
    """
    return jsonify({'Hello': 'World'})
