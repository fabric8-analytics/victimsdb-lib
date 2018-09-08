#!/usr/bin/env python
"""setup.py for victimsdb-lib."""

from setuptools import setup, find_packages


def get_requirements():
    """Parse dependencies from 'requirements.txt' file."""
    with open('requirements.txt') as fd:
        lines = fd.read().splitlines()
        requires, links = [], []
        for line in lines:
            if line.startswith('git+'):
                links.append(line)
            elif line:
                requires.append(line)
        return requires, links


install_requires, dependency_links = get_requirements()


setup(
    name='victimsdb-lib',
    version='0.1.0',
    description='Unofficial library for working with Victims CVE database',
    install_requires=install_requires,
    dependency_links=dependency_links,
    license='Apache-2.0',
    author='Michal Srb',
    author_email='michal@redhat.com',
    url='https://github.com/fabric8-analytics/victimsdb-lib',
    packages=find_packages(exclude=['tests']),
)
