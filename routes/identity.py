"""routes.identity

This module contains all of the routes for authentication and other identity
related activities

Attributes:
    identity_blueprint: The blueprint for these routes
"""
from flask import Blueprint, request, jsonify


identity_blueprint = Blueprint('identity', __name__, url_prefix='/identity')


@identity_blueprint.route('connect/token/', methods=['POST'])
def connect():
    """
    This function processes a log on for the user.

    Depending on the log in method, different parameters are required to be a
    part of the connect string.

    Returns:
        json: Either an error or an access token
    """
    params = request.get_json()
    
    if(params is None):
        request.on_json_loading_failed('Invalid format')

    return jsonify(params)
