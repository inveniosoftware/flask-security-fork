from werkzeug.datastructures import MultiDict

from flask_security.forms import ConfirmRegisterForm


def test_confirm_register_form_runs_password_validator(sqlalchemy_app):
    """Run password validator during confirm register."""
    app = sqlalchemy_app()
    calls = {}

    def fake_validator(password, is_register, **kwargs):
        calls["password"] = password
        calls["is_register"] = is_register
        calls["kwargs"] = kwargs
        return ["too-weak"]

    app.security.password_validator(fake_validator)

    with app.test_request_context("/", method="POST"):
        form = ConfirmRegisterForm(
            formdata=MultiDict({"email": "fresh@example.com", "password": "secret"})
        )
        assert form.validate() is False

    assert calls["password"] == "secret"
    assert calls["is_register"] is True
    assert "password" not in calls["kwargs"]
    assert calls["kwargs"]["email"] == "fresh@example.com"
    assert form.password.errors == ["too-weak"]


def test_confirm_register_form_skips_validator_without_password(
    sqlalchemy_app,
):
    """Skip password validator when no password (e.g., OAuth/SSO)."""
    app = sqlalchemy_app()

    def boom(*args, **kwargs):  # pragma: no cover
        raise AssertionError("validator should not run")

    app.security.password_validator(boom)

    class OAuthConfirmRegisterForm(ConfirmRegisterForm):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._fields.pop("password", None)
            self.password = None

    with app.test_request_context("/", method="POST"):
        form = OAuthConfirmRegisterForm(
            formdata=MultiDict({"email": "oauth@example.com"})
        )
        assert form.validate() is True
        assert form.errors == {}
