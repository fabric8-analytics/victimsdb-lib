"""Error definitions."""


class VictimsDBError(Exception):
    """Generic VictimsDB error."""


class ParseError(VictimsDBError):
    """Error parsing YAML files."""
