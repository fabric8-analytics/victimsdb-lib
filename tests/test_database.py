"""Tests for `victimsdb_lib.database` module."""

import pytest
from victimsdb_lib.database import VictimsDB


def test_from_dir(db_small_path):
    """Test VictimsDB.from_dir()."""
    db = VictimsDB.from_dir(db_small_path)
    assert db


def test_basic(db_small_path):
    """Test VictimsDB.cves_for()."""
    db = VictimsDB.from_dir(db_small_path)
    cves = db.cves_for('werkzeug')
    assert len(cves) == 1
    assert cves[0].cve_id == 'CVE-2016-10516'


def test_java_vulnerabilities(db_small_path):
    """Test VictimsDB.java_vulnerabilities()."""
    db = VictimsDB.from_dir(db_small_path)
    java_db = db.java_vulnerabilities()

    cves = java_db.cves_for('com.google.guava:guava-gwt')
    assert len(cves) == 1
    assert cves[0].cve_id == 'CVE-2018-10237'

    assert not java_db.cves_for('not-there', ecosystem='python')


def test_javascript_vulnerabilities(db_small_path):
    """Test VictimsDB.javascript_vulnerabilities()."""
    db = VictimsDB.from_dir(db_small_path)
    javascript_db = db.javascript_vulnerabilities()

    cves = javascript_db.cves_for('moment')
    assert len(cves) == 1
    assert cves[0].cve_id == 'CVE-2017-18214'

    assert not javascript_db.cves_for('not-there', ecosystem='python')


def test_python_vulnerabilities(db_small_path):
    """Test VictimsDB.python_vulnerabilities()."""
    db = VictimsDB.from_dir(db_small_path)
    python_db = db.python_vulnerabilities()

    cves = python_db.cves_for('werkzeug')
    assert len(cves) == 1
    assert cves[0].cve_id == 'CVE-2016-10516'

    assert not python_db.cves_for('not-there', ecosystem='java')


def test_len(db_small_path):
    """Test len() on VictimsDB()."""
    db = VictimsDB.from_dir(db_small_path)
    assert len(db) == 3


def test_getitem(db_small_path):
    """Test [] on VictimsDB()."""
    db = VictimsDB.from_dir(db_small_path)
    assert 'CVE-2017-18214' == db['CVE-2017-18214'].cve_id

    with pytest.raises(KeyError):
        db['CVE-0000-0000']


def test_iter(db_small_path):
    """Test iter() with VictimsDB()."""
    db = VictimsDB.from_dir(db_small_path)
    wanted = ['CVE-2018-10237', 'CVE-2017-18214', 'CVE-2016-10516']
    for record in db:
        assert record.cve_id in wanted
        wanted.remove(record.cve_id)


def test_contains(db_small_path):
    """Test `in` with VictimsDB()."""
    db = VictimsDB.from_dir(db_small_path)
    assert 'CVE-2018-10237' in db
    assert 'CVE-0000-0000' not in db


def test_merge(db_small_path, db_python_only):
    """Test VictimsDB().merge()."""
    db1 = VictimsDB.from_dir(db_small_path)
    assert len(db1) == 3
    db2 = VictimsDB.from_dir(db_python_only)
    assert len(db2) == 2

    db1.merge(db2)
    assert len(db1) == 4
    cve = db1['CVE-2016-10516']
    assert cve.affects('werkzeug', version='0.11.10')


def test_merge_dont_keep_ours(db_small_path, db_python_only):
    """Test VictimsDB().merge(), but override our records."""
    db1 = VictimsDB.from_dir(db_small_path)
    db2 = VictimsDB.from_dir(db_python_only)

    db1.merge(db2, keep_ours=False)
    assert len(db1) == 4
    cve = db1['CVE-2016-10516']
    assert not cve.affects('werkzeug', version='0.11.10')
