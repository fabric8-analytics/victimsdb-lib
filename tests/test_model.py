"""Tests for `victimsdb_lib.model` module."""

import pytest

from victimsdb_lib.model import VersionRange, Affected, Record
from victimsdb_lib import ParseError


def test_version_range_basic():
    """Basic tests for VersionRange()."""
    version_range = VersionRange('==1.2.0')
    assert '1.2.0' in version_range
    assert '1.0.0' not in version_range
    version_range = VersionRange('<=0')
    assert '1' not in version_range


def test_version_range_advanced():
    """More advanced tests for VersionRange()."""
    version_range = VersionRange('<=1.2.0,1.0.0')
    assert '1.2.0' in version_range
    assert '1.1.0' in version_range
    assert '1.0.0' in version_range
    assert '1.3.0' not in version_range
    assert '0.9.0' not in version_range


def test_affected_basic():
    """Basic tests for Affected()."""
    affected = Affected.from_dict(
        {
            'name': 'my-package',
            'version': ['<=1.0.0'],
            'fixedin': ['>=1.0.1'],
        },
        ecosystem='python'
    )
    assert affected.affects('my-package')
    assert affected.affects('my-package', version='1.0.0')
    assert affected.affects('my-package', version='0.9')

    assert not affected.affects('my-package5')
    assert not affected.affects('my-package5', version='1.0.0')
    assert not affected.affects('my-package', version='1.0.1')


def test_affected_java():
    """Basic tests for Affected(), for Java."""
    affected = Affected.from_dict(
        {
            'groupId': 'my-group',
            'artifactId': 'my-artifact',
            'version': ['<=1.0.0'],
            'fixedin': ['>=1.0.1'],
        },
        ecosystem='java'
    )
    assert affected.affects('my-group:my-artifact')


def test_affected_whitespace():
    """Test how Affected() handles whitespaces in package name."""
    affected = Affected.from_dict(
        {
            'name': ' my-package ',
            'version': ['<=1.0.0'],
            'fixedin': ['>=1.0.1'],
        },
        ecosystem='python'
    )
    assert affected.affects('my-package')


def test_record_java(java_record_path):
    """Test Record(), for Java."""
    record = Record.from_file(java_record_path, 'java')

    assert record.affects('com.google.guava:guava')
    assert not record.affects('com.google.guava:guava-nonexistent')

    assert record.affects('com.google.guava:guava', version='24.1')
    assert record.affects('com.google.guava:guava', version='15.0')
    assert record.affects('com.google.guava:guava', version='11.0')
    assert not record.affects('com.google.guava:guava', version='10.0')

    assert record.affects('com.google.guava:guava-gwt')
    assert record.affects('com.google.guava:guava-gwt', version='24.1')
    assert record.affects('com.google.guava:guava-gwt', version='15.0')
    assert record.affects('com.google.guava:guava-gwt', version='11.0')
    assert not record.affects('com.google.guava:guava-gwt', version='10.0')


def test_record_python(python_record_path):
    """Test Record(), for Python."""
    record = Record.from_file(python_record_path, 'python')

    assert record.affects('werkzeug')
    assert record.affects('werkzeug', version='0.11.10')
    assert record.affects('werkzeug', version='0')
    assert not record.affects('werkzeug', version='1')


def test_record_set(python_record_path):
    """Test hash code."""
    record1 = Record.from_file(python_record_path, 'python')
    record2 = Record.from_file(python_record_path, 'python')

    s = set()
    s.add(record1)
    s.add(record2)
    assert len(s) == 1


def test_invalid_yaml(invalid_record_path):
    """Test ParseError on invalid record."""
    with pytest.raises(ParseError):
        Record.from_file(invalid_record_path, 'python')


def test_str(python_record_path):
    """Test str()."""
    version_range = VersionRange('==1.2.0')
    assert str(version_range) == '==1.2.0'

    affected = Affected.from_dict(
        {'name': 'my-package', 'version': [], 'fixedin': []}, ecosystem='python'
    )
    assert str(affected) == 'my-package'

    record = Record.from_file(python_record_path, 'python')
    assert str(record) == 'CVE-2016-10516'
