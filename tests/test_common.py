# -*- coding: utf-8 -*-
"""
test_common
~~~~~~~~~~~

Test common functionality
"""

from utils import authenticate, logout


def test_login_view(client):
    response = client.get("/login")
    assert b"<h1>Login</h1>" in response.data


def test_authenticate(client):
    response = authenticate(client)
    assert response.status_code == 302
    response = authenticate(client, follow_redirects=True)
    assert b"Hello matt@lp.com" in response.data


def test_authenticate_with_next(client):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=/page1", data=data, follow_redirects=True)
    assert b"Page 1" in response.data


def test_authenticate_with_invalid_next(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http://google.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_with_invalid_malformed_next(client, get_message):
    data = dict(email="matt@lp.com", password="password")
    response = client.post("/login?next=http:///google.com", data=data)
    assert get_message("INVALID_REDIRECT") in response.data


def test_authenticate_case_insensitive_email(app, client):
    response = authenticate(client, "MATT@lp.com", follow_redirects=True)
    assert b"Hello matt@lp.com" in response.data


def test_authenticate_with_invalid_input(client, get_message):
    response = client.post(
        "/login",
        data="{}",
        headers={"Content-Type": "application/json"},
    )
    assert get_message("EMAIL_NOT_PROVIDED") in response.data


def test_login_form(client):
    response = client.post("/login", data={"email": "matt@lp.com"})
    assert b"matt@lp.com" in response.data


def test_unprovided_username(client, get_message):
    response = authenticate(client, "")
    assert get_message("EMAIL_NOT_PROVIDED") in response.data


def test_unprovided_password(client, get_message):
    response = authenticate(client, password="")
    assert get_message("PASSWORD_NOT_PROVIDED") in response.data


def test_invalid_user(client, get_message):
    response = authenticate(client, email="bogus@bogus.com")
    assert get_message("USER_DOES_NOT_EXIST") in response.data


def test_bad_password(client, get_message):
    response = authenticate(client, password="bogus")
    assert get_message("INVALID_PASSWORD") in response.data


def test_inactive_user(client, get_message):
    response = authenticate(client, "tiya@lp.com", "password")
    assert get_message("DISABLED_ACCOUNT") in response.data


def test_unset_password(client, get_message):
    response = authenticate(client, "jess@lp.com", "password")
    assert get_message("PASSWORD_NOT_SET") in response.data


def test_logout(client):
    authenticate(client)
    response = logout(client, follow_redirects=True)
    assert b"Home Page" in response.data


def test_logout_with_next(client, get_message):
    authenticate(client)
    response = client.get("/logout?next=http://google.com")
    assert "google.com" not in response.location


def test_missing_session_access(client, get_message):
    response = client.get("/profile", follow_redirects=True)
    assert get_message("LOGIN") in response.data


def test_has_session_access(client):
    authenticate(client)
    response = client.get("/profile", follow_redirects=True)
    assert b"profile" in response.data


def test_authorized_access(client):
    authenticate(client)
    response = client.get("/admin")
    assert b"Admin Page" in response.data


def test_unauthorized_access(client, get_message):
    authenticate(client, "joe@lp.com")
    response = client.get("/admin", follow_redirects=True)
    assert get_message("UNAUTHORIZED") in response.data


def test_unauthorized_access_with_referrer(client, get_message):
    authenticate(client, "joe@lp.com")
    response = client.get("/admin", headers={"referer": "/admin"})
    assert response.headers["Location"] != "/admin"
    client.get(response.headers["Location"])

    response = client.get(
        "/admin?a=b", headers={"referer": "http://localhost/admin?x=y"}
    )
    assert response.headers["Location"] in ["/", "http://localhost/"]
    client.get(response.headers["Location"])

    response = client.get(
        "/admin", headers={"referer": "/admin"}, follow_redirects=True
    )
    assert response.data.count(get_message("UNAUTHORIZED")) == 1


def test_roles_accepted(client):
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(client, user)
        response = client.get("/admin_or_editor")
        assert b"Admin or Editor Page" in response.data
        logout(client)

    authenticate(client, "jill@lp.com")
    response = client.get("/admin_or_editor", follow_redirects=True)
    assert b"Home Page" in response.data


def test_unauthenticated_role_required(client, get_message):
    response = client.get("/admin", follow_redirects=True)
    assert get_message("UNAUTHORIZED") in response.data


def test_multiple_role_required(client):
    for user in ("matt@lp.com", "joe@lp.com"):
        authenticate(client, user)
        response = client.get("/admin_and_editor", follow_redirects=True)
        assert b"Home Page" in response.data
        client.get("/logout")

    authenticate(client, "dave@lp.com")
    response = client.get("/admin_and_editor", follow_redirects=True)
    assert b"Admin and Editor Page" in response.data


def test_multi_auth_session(client):
    authenticate(
        client,
    )
    response = client.get("/multi_auth")
    assert b"Session" in response.data


def test_user_deleted_during_session_reverts_to_anonymous_user(app, client):
    authenticate(client)

    with app.test_request_context("/"):
        user = app.security.datastore.find_user(email="matt@lp.com")
        app.security.datastore.delete_user(user)
        app.security.datastore.commit()

    response = client.get("/")
    assert b"Hello matt@lp.com" not in response.data


def test_impersonate_user(app, client):
    authenticate(client)
    response = client.get("/")
    assert b"Hello matt@lp.com" in response.data

    # Impersonate
    client.post("/impersonate/joe@lp.com")

    response = client.get("/")
    assert b"Hello matt@lp.com" not in response.data
    assert b"Hello joe@lp.com" in response.data
