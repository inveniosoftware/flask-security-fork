# -*- coding: utf-8 -*-
"""
flask_security
~~~~~~~~~~~~~~

Flask-Security is a Flask extension that aims to add quick and simple
security via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

:copyright: (c) 2012 by Matt Wright.
:license: MIT, see LICENSE for more details.
"""

# Monkey patch Werkzeug 2.1
# Flask-Login uses the safe_str_cmp method which has been removed in Werkzeug
# 2.1. Flask-Login v0.6.0 (yet to be released at the time of writing) fixes the
# issue. Once we depend on Flask-Login v0.6.0 as the minimal version in
# Flask-Security-Invenio/Invenio-Accounts we can remove this patch again.
try:
    # Werkzeug <2.1
    from werkzeug import security

    security.safe_str_cmp
except AttributeError:
    # Werkzeug >=2.1
    import hmac

    from werkzeug import security

    security.safe_str_cmp = hmac.compare_digest

from flask_login import login_required

from .core import AnonymousUser, RoleMixin, Security, UserMixin, current_user
from .datastore import SQLAlchemySessionUserDatastore, SQLAlchemyUserDatastore
from .decorators import auth_required, roles_accepted, roles_required
from .forms import (
    ConfirmRegisterForm,
    ForgotPasswordForm,
    LoginForm,
    RegisterForm,
    ResetPasswordForm,
)
from .signals import (
    confirm_instructions_sent,
    password_reset,
    reset_password_instructions_sent,
    user_confirmed,
    user_registered,
)
from .utils import impersonate_user, login_user, logout_user, url_for_security

__version__ = "3.5.0"
__all__ = (
    "AnonymousUser",
    "auth_required",
    "confirm_instructions_sent",
    "ConfirmRegisterForm",
    "current_user",
    "ForgotPasswordForm",
    "impersonate_user",
    "login_required",
    "login_user",
    "LoginForm",
    "logout_user",
    "password_reset",
    "RegisterForm",
    "reset_password_instructions_sent",
    "ResetPasswordForm",
    "RoleMixin",
    "roles_accepted",
    "roles_required",
    "Security",
    "SQLAlchemySessionUserDatastore",
    "SQLAlchemyUserDatastore",
    "url_for_security",
    "user_confirmed",
    "user_registered",
    "UserMixin",
)
