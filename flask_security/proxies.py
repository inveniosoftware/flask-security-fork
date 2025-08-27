# -*- coding: utf-8 -*-
"""
flask_security.proxies
~~~~~~~~~~~~~~~~~~~~~~
"""

from flask import current_app
from werkzeug.local import LocalProxy

_security = LocalProxy(lambda: current_app.extensions["security"])
