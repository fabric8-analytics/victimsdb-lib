"""Public API."""

from victimsdb_lib.database import VictimsDB
from victimsdb_lib.errors import VictimsDBError, ParseError

# to fix dead code detector issues
assert VictimsDB
assert VictimsDBError
assert ParseError
