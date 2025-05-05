# -*- coding: utf-8 -*-
"""
flask_security.datastore
~~~~~~~~~~~~~~~~~~~~~~~~

This module contains an user datastore classes.

:copyright: (c) 2012 by Matt Wright.
:license: MIT, see LICENSE for more details.
"""
import warnings

from .utils import get_identity_attributes


class Datastore(object):
    def __init__(self, db):
        self.db = db

    def commit(self):
        pass

    def put(self, model):
        raise NotImplementedError

    def delete(self, model):
        raise NotImplementedError


class SQLAlchemyDatastore(Datastore):
    def commit(self):
        self.db.session.commit()

    def put(self, model):
        self.db.session.add(model)
        return model

    def delete(self, model):
        self.db.session.delete(model)


class UserDatastore(object):
    """Abstracted user datastore.

    :param user_model: A user model class definition
    :param role_model: A role model class definition
    """

    def __init__(self, user_model, role_model):
        self.user_model = user_model
        self.role_model = role_model

    def _prepare_role_modify_args(self, user, role):
        if isinstance(user, str):
            user = self.find_user(email=user)
        if isinstance(role, str):
            role = self.find_role(role)
        return user, role

    def _prepare_create_user_args(self, **kwargs):
        kwargs.setdefault("active", True)
        roles = kwargs.get("roles", [])
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        kwargs["roles"] = roles
        return kwargs

    def get_user(self, id_or_email):
        """Returns a user matching the specified ID or email address."""
        raise NotImplementedError

    def get_user_by_email(self, email):
        """Returns a user matching the specified email address."""
        raise NotImplementedError

    def get_user_by_id(self, id):
        """Returns a user matching the specified ID."""
        raise NotImplementedError

    def find_user(self, *args, **kwargs):
        """Returns a user matching the provided parameters."""
        raise NotImplementedError

    def find_role(self, *args, **kwargs):
        """Returns a role matching the provided name."""
        raise NotImplementedError

    def add_role_to_user(self, user, role):
        """Adds a role to a user.

        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        if role not in user.roles:
            user.roles.append(role)
            self.put(user)
            return True
        return False

    def remove_role_from_user(self, user, role):
        """Removes a role from a user.

        :param user: The user to manipulate
        :param role: The role to remove from the user
        """
        rv = False
        user, role = self._prepare_role_modify_args(user, role)
        if role in user.roles:
            rv = True
            user.roles.remove(role)
            self.put(user)
        return rv

    def toggle_active(self, user):
        """Toggles a user's active status. Always returns True."""
        user.active = not user.active
        return True

    def deactivate_user(self, user):
        """Deactivates a specified user. Returns `True` if a change was made.

        :param user: The user to deactivate
        """
        if user.active:
            user.active = False
            return True
        return False

    def activate_user(self, user):
        """Activates a specified user. Returns `True` if a change was made.

        :param user: The user to activate
        """
        if not user.active:
            user.active = True
            return True
        return False

    def create_role(self, **kwargs):
        """Creates and returns a new role from the given parameters."""

        role = self.role_model(**kwargs)
        return self.put(role)

    def find_or_create_role(self, name, **kwargs):
        """Returns a role matching the given name or creates it with any
        additionally provided parameters.
        """
        kwargs["name"] = name
        return self.find_role(name) or self.create_role(**kwargs)

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters."""
        kwargs = self._prepare_create_user_args(**kwargs)
        user = self.user_model(**kwargs)
        return self.put(user)

    def delete_user(self, user):
        """Deletes the specified user.

        :param user: The user to delete
        """
        self.delete(user)


class SQLAlchemyUserDatastore(SQLAlchemyDatastore, UserDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security that assumes the
    use of the Flask-SQLAlchemy extension.
    """

    def __init__(self, db, user_model, role_model):
        SQLAlchemyDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)

    def _is_numeric(self, value):
        try:
            int(value)
        except (TypeError, ValueError):
            return False
        return True

    def get_user(self, identifier):
        warnings.warn(
            "get_user method is deprecated, user get_user_by_email/get_user_by_id",
            DeprecationWarning,
        )
        from sqlalchemy import func as alchemyFn

        if self._is_numeric(identifier):
            return self.db.session.get(self.user_model, identifier)
        for attr in get_identity_attributes():
            query = alchemyFn.lower(getattr(self.user_model, attr)) == alchemyFn.lower(
                identifier
            )
            rv = self.user_model.query.filter(query).first()
            if rv is not None:
                return rv

    def get_user_by_email(self, identifier):
        from sqlalchemy import func as alchemyFn

        for attr in get_identity_attributes():
            query = alchemyFn.lower(getattr(self.user_model, attr)) == alchemyFn.lower(
                identifier
            )
            rv = self.user_model.query.filter(query).first()
            if rv is not None:
                return rv

    def get_user_by_id(self, identifier):
        return self.user_model.query.get(identifier)

    def find_user(self, **kwargs):
        return self.user_model.query.filter_by(**kwargs).first()

    def find_role(self, role):
        return self.role_model.query.filter_by(name=role).first()


class SQLAlchemySessionUserDatastore(SQLAlchemyUserDatastore, SQLAlchemyDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security that assumes the
    use of the flask_sqlalchemy_session extension.
    """

    def __init__(self, session, user_model, role_model):

        class PretendFlaskSQLAlchemyDb(object):
            """This is a pretend db object, so we can just pass in a session."""

            def __init__(self, session):
                self.session = session

        SQLAlchemyUserDatastore.__init__(
            self, PretendFlaskSQLAlchemyDb(session), user_model, role_model
        )
