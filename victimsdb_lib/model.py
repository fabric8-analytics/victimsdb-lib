"""VictimsDB model."""

import re
import yaml
from f8a_version_comparator.comparable_version import ComparableVersion

from victimsdb_lib.errors import ParseError


class Record(object):
    """CVE Record in a database."""

    def __init__(self, cve_id, title, description, cvss_v2, references, affected):
        if cve_id:
            cve_id = cve_id.strip()
            if not cve_id.startswith('CVE-'):
                cve_id = 'CVE-{cve_id}'.format(cve_id=cve_id)
        self.cve_id = cve_id
        self.title = title or ''
        self.description = description or ''
        self.cvss_v2 = cvss_v2 or ''
        self.references = references or []
        self.affected = affected

    def affects(self, name, version=None):
        """Check if package with given name is affected by this CVE."""
        for entry in self.affected:
            if entry.affects(name, version):
                return True
        return False

    @classmethod
    def from_dict(cls, record_dict, ecosystem):
        """Build record from dict."""
        try:
            cve_id = record_dict['cve']
            title = record_dict.get('title')
            description = record_dict.get('description')
            cvss_v2 = record_dict.get('cvss_v2')
            references = record_dict.get('references')
            affected = [Affected.from_dict(x, ecosystem) for x in record_dict.get('affected')]
        except KeyError as e:
            raise ParseError('Missing key "{k}"'.format(k=e.args[0]))
        return cls(
            cve_id=cve_id,
            title=title,
            description=description,
            cvss_v2=cvss_v2,
            references=references,
            affected=affected
        )

    @classmethod
    def from_file(cls, yaml_path, ecosystem):
        """Build record from YAML file."""
        with open(yaml_path, 'r') as f:
            try:
                yaml_dict = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ParseError('Unable to parse "{f}": {m}'.format(f=yaml_path, m=str(e)))
        return cls.from_dict(yaml_dict, ecosystem)

    def __hash__(self):
        return self.cve_id.__hash__()

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if other.cve_id == self.cve_id:
            return True
        return False

    def __str__(self):
        return self.cve_id

    def __repr__(self):
        return '<Record(cve_id={cve_id})>'.format(cve_id=self.cve_id)


class Affected(object):
    """Section of the `Record` which holds information about package names and version ranges."""

    def __init__(self, name, version, fixedin):

        self.name = name.strip()
        self.version = version or []
        self.fixedin = fixedin or []

    def affects(self, name, version=None):
        """Check if package with given name is affected."""
        if name != self.name:
            return False

        if version is not None:
            for version_range in self.version:
                if version in version_range:
                    return True
            else:
                return False

        return True

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Affected(name={name})>'.format(name=self.name)

    @classmethod
    def from_dict(cls, affected_dict, ecosystem):
        """Build from dict."""
        try:
            if ecosystem == 'java':
                gid = affected_dict['groupId']
                aid = affected_dict['artifactId']
                name = '{g}:{a}'.format(g=gid, a=aid)
            else:
                name = affected_dict['name']

            version = [VersionRange(x) for x in affected_dict.get('version', [])]
            fixedin = [VersionRange(x) for x in affected_dict.get('fixedin', [])]

            return cls(name=name, version=version, fixedin=fixedin)
        except KeyError as e:
            raise ParseError('Missing key "{k}"'.format(k=e.args[0]))


class VersionRange(object):
    """Representation of a version range."""

    def __init__(self, version_str):
        self._version_str = version_str.strip()

        # https://github.com/victims/victims-cve-db#version-string-common
        result = re.fullmatch(r'^[><=]{1}=[^, ]+(,[^, ]+)?$', version_str.strip())
        if result is None:
            raise ParseError('Invalid version string: {vs}'.format(vs=version_str))

        self._operator = self._version_str[:2]

        if ',' in self._version_str:
            self._version = ComparableVersion(self._version_str[2:].split(',')[0])
            self._explicit_boundary = ComparableVersion(self._version_str.split(',')[1])
        else:
            self._version = ComparableVersion(self._version_str[2:])
            self._explicit_boundary = None

    def __str__(self):
        return self._version_str

    def __repr__(self):
        return '<VersionRange(version_str={vs})>'.format(vs=self._version_str)

    def __contains__(self, version):
        """Return True if `checked_version` is among `affected_versions`."""
        checked_version = ComparableVersion(version)

        # TODO: we are probably missing '>=' here; but do we need it?
        if self._operator == '==':
            if checked_version == self._version:
                return True
        elif self._operator == '<=':
            if self._explicit_boundary:
                if self._explicit_boundary <= checked_version <= self._version:
                    return True
            else:
                if checked_version <= self._version:
                    return True

        return False
