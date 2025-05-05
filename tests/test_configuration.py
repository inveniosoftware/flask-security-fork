# -*- coding: utf-8 -*-
"""
test_configuration
~~~~~~~~~~~~~~~~~~

Basic configuration tests
"""

import pytest
from utils import authenticate, logout


@pytest.mark.settings(
    logout_url="/custom_logout",
    login_url="/custom_login",
    post_login_view="/post_login",
    post_logout_view="/post_logout",
    default_http_auth_realm="Custom Realm",
)
def test_view_configuration(client):
    response = client.get("/custom_login")
    assert b"<h1>Login</h1>" in response.data

    response = authenticate(client, endpoint="/custom_login")
    assert "location" in response.headers
    assert response.headers["Location"] in [
        "/post_login",
        "http://localhost/post_login",
    ]

    response = logout(client, endpoint="/custom_logout")
    assert "location" in response.headers
    assert response.headers["Location"] in [
        "/post_logout",
        "http://localhost/post_logout",
    ]


@pytest.mark.settings(login_user_template="custom_security/login_user.html")
def test_template_configuration(client):
    response = client.get("/login")
    assert b"CUSTOM LOGIN USER" in response.data
