# -*- coding: utf-8 -*-
"""
conftest
~~~~~~~~

Test fixtures and what not

:copyright: (c) 2017 by CERN.
:license: MIT, see LICENSE for more details.
"""

import os
import tempfile
from json import JSONEncoder as BaseEncoder

import pytest
from flask import Flask, current_app, render_template
from flask_babel import Babel
from flask_mail import Mail
from speaklater import is_lazy_string
from utils import Response, populate_data

from flask_security import (
    RoleMixin,
    Security,
    SQLAlchemySessionUserDatastore,
    SQLAlchemyUserDatastore,
    UserMixin,
    auth_required,
    impersonate_user,
    login_required,
    roles_accepted,
    roles_required,
)


class JSONEncoder(BaseEncoder):
    def default(self, o):
        if is_lazy_string(o):
            return str(o)

        return BaseEncoder.default(self, o)


@pytest.fixture()
def app(request):
    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config["SECRET_KEY"] = "secret"
    app.config["TESTING"] = True
    app.config["LOGIN_DISABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    app.config["SECURITY_PASSWORD_SALT"] = "salty"

    for opt in [
        "changeable",
        "recoverable",
        "registerable",
        "trackable",
        "confirmable",
    ]:
        app.config["SECURITY_" + opt.upper()] = opt in request.keywords

    pytest_major = int(pytest.__version__.split(".")[0])
    if pytest_major >= 4:
        marker_getter = request.node.get_closest_marker
    else:
        marker_getter = request.keywords.get
    settings = marker_getter("settings")
    babel = marker_getter("babel")
    if settings is not None:
        for key, value in settings.kwargs.items():
            app.config["SECURITY_" + key.upper()] = value

    mail = Mail(app)
    if babel is None or babel.args[0]:
        babel = Babel(app)
        app.babel = babel
    app.json_provider_class = JSONEncoder
    app.mail = mail

    @app.route("/")
    def index():
        return render_template("index.html", content="Home Page")

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("index.html", content="Profile Page")

    @app.route("/post_login")
    @login_required
    def post_login():
        return render_template("index.html", content="Post Login")

    @app.route("/multi_auth")
    @auth_required(
        "session",
    )
    def multi_auth():
        return render_template("index.html", content="Session, Token, Basic auth")

    @app.route("/post_logout")
    def post_logout():
        return render_template("index.html", content="Post Logout")

    @app.route("/post_register")
    def post_register():
        return render_template("index.html", content="Post Register")

    @app.route("/admin")
    @roles_required("admin")
    def admin():
        return render_template("index.html", content="Admin Page")

    @app.route("/admin_and_editor")
    @roles_required("admin", "editor")
    def admin_and_editor():
        return render_template("index.html", content="Admin and Editor Page")

    @app.route("/admin_or_editor")
    @roles_accepted("admin", "editor")
    def admin_or_editor():
        return render_template("index.html", content="Admin or Editor Page")

    @app.route("/unauthorized")
    def unauthorized():
        return render_template("unauthorized.html")

    @app.route("/page1")
    def page_1():
        return "Page 1"

    @login_required
    @app.route("/impersonate/<user>", methods=["POST"])
    def impersonate(user):
        from flask import g

        user = current_app.security.datastore.get_user(user)

        impersonate_user(user, g.identity)
        return "Page 1"

    def delete_user_from_g(exception):
        """Delete user from `flask.g` when the request is tearing down.
        Flask-login==0.6.2 changed the way the user is saved i.e uses `flask.g`.
        Flask.g is pointing to the application context which is initialized per
        request. That said, `pytest-flask` is pushing an application context on each
        test initialization that causes problems as subsequent requests during a test
        are detecting the active application request and not popping it when the
        sub-request is tearing down. That causes the logged in user to remain cached
        for the whole duration of the test. To fix this, we add an explicit teardown
        handler that will pop out the logged in user in each request and it will force
        the user to be loaded each time.
        """
        from flask import g

        if "_login_user" in g:
            del g._login_user

    app.teardown_request(delete_user_from_g)

    return app


@pytest.fixture()
def sqlalchemy_datastore(request, app, tmpdir):
    from flask_sqlalchemy import SQLAlchemy

    f, path = tempfile.mkstemp(
        prefix="flask-security-test-db", suffix=".db", dir=str(tmpdir)
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + path
    db = SQLAlchemy(app)

    roles_users = db.Table(
        "roles_users",
        db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
        db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
    )

    class Role(db.Model, RoleMixin):
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(80), unique=True)
        description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True)
        username = db.Column(db.String(255))
        password = db.Column(db.String(255))
        last_login_at = db.Column(db.DateTime())
        current_login_at = db.Column(db.DateTime())
        last_login_ip = db.Column(db.String(100))
        current_login_ip = db.Column(db.String(100))
        login_count = db.Column(db.Integer)
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship(
            "Role", secondary=roles_users, backref=db.backref("users", lazy="dynamic")
        )

    with app.app_context():
        db.create_all()

    yield SQLAlchemyUserDatastore(db, User, Role)

    os.close(f)
    os.remove(path)


@pytest.fixture()
def sqlalchemy_session_datastore(request, app, tmpdir):
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        ForeignKey,
        Integer,
        String,
        create_engine,
    )
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import backref, relationship, scoped_session, sessionmaker

    f, path = tempfile.mkstemp(
        prefix="flask-security-test-db", suffix=".db", dir=str(tmpdir)
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + path

    engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])
    db_session = scoped_session(
        sessionmaker(autocommit=False, autoflush=False, bind=engine)
    )
    Base = declarative_base()
    Base.query = db_session.query_property()

    class RolesUsers(Base):
        __tablename__ = "roles_users"
        id = Column(Integer(), primary_key=True)
        user_id = Column("user_id", Integer(), ForeignKey("user.id"))
        role_id = Column("role_id", Integer(), ForeignKey("role.id"))

    class Role(Base, RoleMixin):
        __tablename__ = "role"
        id = Column(Integer(), primary_key=True)
        name = Column(String(80), unique=True)
        description = Column(String(255))

    class User(Base, UserMixin):
        __tablename__ = "user"
        id = Column(Integer, primary_key=True)
        email = Column(String(255), unique=True)
        username = Column(String(255))
        password = Column(String(255))
        last_login_at = Column(DateTime())
        current_login_at = Column(DateTime())
        last_login_ip = Column(String(100))
        current_login_ip = Column(String(100))
        login_count = Column(Integer)
        active = Column(Boolean())
        confirmed_at = Column(DateTime())
        roles = relationship(
            "Role", secondary="roles_users", backref=backref("users", lazy="dynamic")
        )

    with app.app_context():
        Base.metadata.create_all(bind=engine)

    yield SQLAlchemySessionUserDatastore(db_session, User, Role)

    db_session.close()
    os.close(f)
    os.remove(path)


@pytest.fixture()
def sqlalchemy_app(app, sqlalchemy_datastore):
    def create():
        app.security = Security(app, datastore=sqlalchemy_datastore)
        return app

    return create


@pytest.fixture()
def sqlalchemy_session_app(app, sqlalchemy_session_datastore):
    def create():
        app.security = Security(app, datastore=sqlalchemy_session_datastore)
        return app

    return create


@pytest.fixture()
def client(request, sqlalchemy_app):
    app = sqlalchemy_app()
    populate_data(app)
    return app.test_client()


@pytest.fixture()
def in_app_context(request, sqlalchemy_app):
    app = sqlalchemy_app()
    with app.app_context():
        yield app


@pytest.fixture()
def get_message(app):
    def fn(key, **kwargs):
        rv = app.config["SECURITY_MSG_" + key][0] % kwargs
        return rv.encode("utf-8")

    return fn


@pytest.fixture(params=["sqlalchemy", "sqlalchemy-session"])
def datastore(request, sqlalchemy_datastore, sqlalchemy_session_datastore):
    if request.param == "sqlalchemy":
        rv = sqlalchemy_datastore
    elif request.param == "sqlalchemy-session":
        rv = sqlalchemy_session_datastore
    return rv


@pytest.fixture()
def cli_app(app, datastore):
    def create_app():
        app.config.update(
            **{"SECURITY_USER_IDENTITY_ATTRIBUTES": ("email", "username")}
        )
        app.security = Security(app, datastore=datastore)
        return app

    return create_app()
