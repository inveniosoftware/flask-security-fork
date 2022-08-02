# -*- coding: utf-8 -*-
"""
    test_trackable
    ~~~~~~~~~~~~~~

    Trackable tests
"""

import pytest
from flask import after_this_request, redirect
from utils import authenticate, logout
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_security import login_user

pytestmark = pytest.mark.trackable()


def _client_ip(client):
    """Compatibility layer for Flask<0.12."""
    return getattr(client, "environ_base", {}).get("REMOTE_ADDR")


def test_trackable_flag(base_app, client):
    base_app.wsgi_app = ProxyFix(base_app.wsgi_app, x_for=1)
    e = "matt@lp.com"
    authenticate(client, email=e)
    logout(client)
    authenticate(client, email=e, headers={"X-Forwarded-For": "127.0.0.1"})

    with base_app.app_context():
        user = base_app.security.datastore.find_user(email=e)
        assert user.last_login_at is not None
        assert user.current_login_at is not None
        assert user.last_login_ip == _client_ip(client)
        assert user.current_login_ip == "127.0.0.1"
        assert user.login_count == 2


def test_trackable_with_multiple_ips_in_headers(base_app, client):
    base_app.wsgi_app = ProxyFix(base_app.wsgi_app, x_for=2)

    e = "matt@lp.com"
    authenticate(client, email=e)
    logout(client)
    authenticate(
        client,
        email=e,
        headers={"X-Forwarded-For": "99.99.99.99, 88.88.88.88, 77.77.77.77"},
    )

    with base_app.app_context():
        user = base_app.security.datastore.find_user(email=e)
        assert user.last_login_at is not None
        assert user.current_login_at is not None
        assert user.last_login_ip == _client_ip(client)
        assert user.current_login_ip == "88.88.88.88"
        assert user.login_count == 2


def test_trackable_using_login_user(base_app, client):
    """
    This tests is only to serve as an example of how one needs to call
    datastore.commit() after logging a user in to make sure the trackable
    fields are saved to the datastore.
    """
    base_app.wsgi_app = ProxyFix(base_app.wsgi_app, x_for=1)

    @base_app.route("/login_custom", methods=["POST"])
    def login_custom():
        user = base_app.security.datastore.find_user(email=e)
        login_user(user)

        @after_this_request
        def save_user(response):
            base_app.security.datastore.commit()
            return response

        return redirect("/")

    e = "matt@lp.com"
    authenticate(client, email=e)
    logout(client)

    data = dict(email=e, password="password")
    client.post("/login_custom", data=data, headers={"X-Forwarded-For": "127.0.0.1"})

    with base_app.app_context():
        user = base_app.security.datastore.find_user(email=e)
        assert user.last_login_at is not None
        assert user.current_login_at is not None
        assert user.last_login_ip == _client_ip(client)
        assert user.current_login_ip == "127.0.0.1"
        assert user.login_count == 2
