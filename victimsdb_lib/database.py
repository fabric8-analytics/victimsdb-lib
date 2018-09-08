"""Wrapper around Victims database."""

import os
import tempfile
import subprocess
import logging

from victimsdb_lib.model import Record
from victimsdb_lib.errors import ParseError

_logger = logging.getLogger(__name__)


class VictimsDB(object):
    """Wrapper around Victims database."""

    def __init__(self, records, _ecosystem=None):
        self._records = records or dict()
        self._ecosystem = _ecosystem

    def java_vulnerabilities(self):
        """Get VictimsDB instance containing only Java vulnerabilities."""
        ecosystem = 'java'
        return VictimsDB(
            records={ecosystem: self._records.get(ecosystem, set())}, _ecosystem=ecosystem
        )

    def javascript_vulnerabilities(self):
        """Get VictimsDB instance containing only JavaScript vulnerabilities."""
        ecosystem = 'javascript'
        return VictimsDB(
            records={ecosystem: self._records.get(ecosystem, set())}, _ecosystem=ecosystem
        )

    def python_vulnerabilities(self):
        """Get VictimsDB instance containing only Python vulnerabilities."""
        ecosystem = 'python'
        return VictimsDB(
            records={ecosystem: self._records.get(ecosystem, set())}, _ecosystem=ecosystem
        )

    def cves_for(self, name, ecosystem=None):
        """Get list of `victimsdb_lib.Record` instances which affect given package."""
        results = []
        if not ecosystem:
            ecosystem = self._ecosystem
        for curr_ecosystem, records in self._records.items():
            if ecosystem and curr_ecosystem != ecosystem:
                continue
            for record in records:
                if record.affects(name=name):
                    results.append(record)
        return results

    def merge(self, other_db, keep_ours=True):
        """Merge records from `other_db` into this instance."""
        other_records = {
            'java': other_db.java_vulnerabilities(),
            'javascript': other_db.javascript_vulnerabilities(),
            'python': other_db.python_vulnerabilities()
        }
        for ecosystem, records in other_records.items():
            self._merge_ecosystem(ecosystem, records, keep_ours)

    def _merge_ecosystem(self, ecosystem, records, keep_ours=True):
        for record in records:
            if record not in self._records[ecosystem] or not keep_ours:
                self._records[ecosystem].discard(record)
                self._records[ecosystem].add(record)

    @classmethod
    def from_dir(cls, db_dir):
        """Build database from directory."""
        records = {
            'java': set(),
            'javascript': set(),
            'python': set()
        }

        for ecosystem in records.keys():
            db_dir_lang = os.path.join(db_dir, ecosystem)
            for dirpath, dirnames, filenames in os.walk(db_dir_lang):
                for filename in filenames:
                    if not filename.endswith(('.yaml', '.yml')):
                        continue
                    try:
                        fullpath = os.path.join(dirpath, filename)
                        record = Record.from_file(fullpath, ecosystem)
                        records[ecosystem].add(record)
                    except ParseError as e:
                        _logger.warning(str(e))
        return cls(records=records)

    @classmethod
    def from_git_url(cls, git_url):
        """Build database from GIT URL."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = ['git', 'clone', '--single-branch', '--depth=1', git_url, temp_dir]
            subprocess.check_call(cmd)
            db_dir = os.path.join(temp_dir, 'database')
            return cls.from_dir(db_dir=db_dir)

    def __contains__(self, cve_id):
        if not cve_id:
            return False

        for records in self._records.values():
            for record in records:
                if record.cve_id == cve_id:
                    return True
        return False

    def __getitem__(self, cve_id):
        for records in self._records.values():
            for record in records:
                if record.cve_id == cve_id:
                    return record
        raise KeyError(cve_id)

    def __iter__(self):
        # TODO: perf(?)
        iter_set = set()
        for records in self._records.values():
            if records:
                iter_set = iter_set.union(records)
        return iter(iter_set)

    def __len__(self):
        total = 0
        for records in self._records.values():
            total += len(records)
        return total

    def __bool__(self):
        return bool(len(self))
