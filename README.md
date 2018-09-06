# victimsdb-lib

This is an unofficial library for working with Victims CVE database.


## Examples

```python
>>> from victimsdb_lib import VictimsDB

>>> db = VictimsDB.from_dir('database/')
# or VictimsDB.from_git_url('https://github.com/fabric8-analytics/cvedb.git')

>>> 'CVE-2018-1000164' in db
True

>>> notebook_cves = db.cves_for('notebook', ecosystem='python')
>>> len(notebook_cves)
1

>>> cve = notebook_cves[0]
>>> cve.affects('notebook', version='5.0.0')
True

>>> cve.affects('notebook', version='5.5.0')
False
```
