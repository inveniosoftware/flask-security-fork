#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 CERN.
#
# Flask-Security-Invenio is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

# Quit on errors
set -o errexit

# Quit on unbound symbols
set -o nounset

# Check for arguments
pytest_args=()
for arg in $@; do
	case ${arg} in
		*)
			pytest_args+=( ${arg} )
			;;
	esac
done

python -m check_manifest --ignore ".*-requirements.txt"
python -m sphinx.cmd.build -qnN docs docs/_build/html
python -m pytest ${pytest_args[@]+"${pytest_args[@]}"}
tests_exit_code=$?
exit "$tests_exit_code"
