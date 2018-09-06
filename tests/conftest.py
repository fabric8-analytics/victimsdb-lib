"""Test utils."""

import os
import pytest


_here = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture
def db_small_path():
    """Path to the small test database."""
    return os.path.join(_here, 'fixtures/databases/db-small/database')


@pytest.fixture
def db_python_only():
    """Path to the python-only test database."""
    return os.path.join(_here, 'fixtures/databases/db-python-only/database')


@pytest.fixture
def java_record_path():
    """Path to the Java CVE record."""
    return os.path.join(_here, 'fixtures/records/java-2018-10237.yaml')


@pytest.fixture
def python_record_path():
    """Path to the Python CVE record."""
    return os.path.join(_here, 'fixtures/records/python-2016-10516.yaml')


@pytest.fixture
def invalid_record_path():
    """Path to the invalid CVE record."""
    return os.path.join(_here, 'fixtures/records/invalid.yaml')
