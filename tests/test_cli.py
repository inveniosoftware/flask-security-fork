# -*- coding: utf-8 -*-
"""
test_cli
~~~~~~~~

Test command line interface.
"""

from flask_security.cli import (
    roles_add,
    roles_create,
    roles_remove,
    users_activate,
    users_create,
    users_deactivate,
)


def test_cli_createuser(cli_app):
    """Test create user CLI."""
    runner = cli_app.test_cli_runner()

    # Missing params
    result = runner.invoke(users_create, input="1234\n1234\n")
    assert result.exit_code != 0

    # Create user with invalid email
    result = runner.invoke(users_create, ["not-an-email", "--password", "123456"])
    assert result.exit_code == 2

    # Create user
    result = runner.invoke(users_create, ["email@test.org", "--password", "123456"])
    assert result.exit_code == 0


def test_cli_createrole(cli_app):
    """Test create user CLI."""
    runner = cli_app.test_cli_runner()

    # Missing params
    result = runner.invoke(roles_create, ["-d", "Test description"])
    assert result.exit_code != 0

    # Create role
    result = runner.invoke(roles_create, ["superusers", "-d", "Test description"])
    assert result.exit_code == 0


def test_cli_addremove_role(cli_app):
    """Test add/remove role."""
    runner = cli_app.test_cli_runner()

    # Create a user and a role
    result = runner.invoke(users_create, ["a@test.org", "--password", "123456"])
    assert result.exit_code == 0
    result = runner.invoke(roles_create, ["superuser"])
    assert result.exit_code == 0

    # User not found
    result = runner.invoke(roles_add, ["inval@test.org", "superuser"])
    assert result.exit_code != 0

    # Add:
    result = runner.invoke(roles_add, ["a@test.org", "invalid"])
    assert result.exit_code != 0

    result = runner.invoke(roles_remove, ["inval@test.org", "superuser"])
    assert result.exit_code != 0

    # Remove:
    result = runner.invoke(roles_remove, ["a@test.org", "invalid"])
    assert result.exit_code != 0

    result = runner.invoke(roles_remove, ["b@test.org", "superuser"])
    assert result.exit_code != 0

    result = runner.invoke(roles_remove, ["a@test.org", "superuser"])
    assert result.exit_code != 0

    # Add:
    result = runner.invoke(roles_add, ["a@test.org", "superuser"])
    assert result.exit_code == 0
    result = runner.invoke(roles_add, ["a@test.org", "superuser"])
    assert result.exit_code != 0

    # Remove:
    result = runner.invoke(roles_remove, ["a@test.org", "superuser"])
    assert result.exit_code == 0


def test_cli_activate_deactivate(cli_app):
    """Test create user CLI."""
    runner = cli_app.test_cli_runner()

    # Create a user
    result = runner.invoke(users_create, ["a@test.org", "--password", "123456"])
    assert result.exit_code == 0

    # Activate
    result = runner.invoke(users_activate, ["in@valid.org"])
    assert result.exit_code != 0
    result = runner.invoke(users_deactivate, ["in@valid.org"])
    assert result.exit_code != 0

    result = runner.invoke(users_activate, ["a@test.org"])
    assert result.exit_code == 0
    result = runner.invoke(users_activate, ["a@test.org"])
    assert result.exit_code == 0

    # Deactivate
    result = runner.invoke(users_deactivate, ["a@test.org"])
    assert result.exit_code == 0
    result = runner.invoke(users_deactivate, ["a@test.org"])
    assert result.exit_code == 0
