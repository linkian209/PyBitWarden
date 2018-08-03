"""routes.icons

This module contains all of the routes for getting icons

Attributes:
    icons_blueprint: The blueprint for these routes
"""
from flask import Blueprint, redirect

icons_blueprint = Blueprint('icons', __name__, url_prefix='/icons')


@icons_blueprint.route('<path:domain>/icon.png', methods=['GET'])
def icon(domain):
    """
    Gets the icon for the inputted domain

    Args:
        :param domain: The domain needing the icon

    Returns:
        redirect: Redirects to the website's favicon
    """
    print(domain)
    return redirect('{}/favicon.ico'.format(domain))
