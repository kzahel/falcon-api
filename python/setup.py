#!/usr/bin/env python
#
#

__author__ = 'Kyle Graehl'
__author_email__ = 'kgraehl@gmail.com'

from setuptools import setup, find_packages

setup(
    name = "falcon_api",
    version = "0.1",
    packages = find_packages(),
    author = __author__,
    author_email = __author_email__,
    description = "falcon api",
    install_requires = ['tornado'],
    package_data = {
        "": ['data/*', 'data/.*'],
        },
    )
