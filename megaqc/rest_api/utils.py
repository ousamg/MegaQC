import os
from enum import IntEnum, auto
from functools import wraps
from uuid import uuid4

from flask import request
from flask.globals import current_app
from flask_login import current_user
from flapison.exceptions import AccessDenied, JsonApiException
from megaqc.user.models import User


def get_upload_dir():
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    if not os.path.isdir(upload_dir):
        os.mkdir(upload_dir)

    return upload_dir


def get_unique_filename():
    dir = get_upload_dir()
    while True:
        proposed = os.path.join(dir, str(uuid4()))
        if not os.path.exists(proposed):
            return proposed


class Permission(IntEnum):
    VIEWER = auto()
    USER = auto()
    ADMIN = auto()


def permission_manager(view, view_args, view_kwargs, *args, **kwargs):
    """
    Authenticates a user via flask.current_user for web sessions or request.header
    access_token for direct API calls (and with that precedence). Adds the kwargs
    "user", "permission" and "auth_method" to the view function.

    :param callable view: the view
    :param list view_args: view args
    :param dict view_kwargs: view kwargs
    :param list args: decorator args
    :param dict kwargs: decorator kwargs
    """

    user = None
    auth_method = None
    if not current_user.is_anonymous:
        user = User.query.filter_by(user_id=current_user.user_id).first()
        auth_method = "current_user"
    elif request.headers.get("access_token") is not None:
        user = User.query.filter_by(api_token=request.headers["access_token"]).first()
        auth_method = "access_token"

    if user is None:
        if auth_method is None:
            raise JsonApiException(
                "missing token", title="Not authorized", status=401, code=401
            )
        elif auth_method == "access_token":
            current_app.logger.debug(
                f"Invalid token used: {request.headers['access_token']} - {request.method} {request.url}"
            )
            raise AccessDenied("invalid token")
        else:
            current_app.logger.warn(
                f"Failed to find current_user {current_user.user_id}, "
                f"something really weird happened - {request.method} {request.url}"
            )
            raise AccessDenied("User Not Found", status=404, code=404)

    current_app.logger.debug(
        f"authing user {user.username} via {auth_method} - {request.method} {request.url}"
    )
    view_kwargs["user"] = user
    view_kwargs["auth_method"] = auth_method
    if user.is_admin:
        view_kwargs["permission"] = Permission.ADMIN
    else:
        view_kwargs["permission"] = Permission.USER
