#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import codecs
import os
import re

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from email.utils import parseaddr

def open_local(paths, mode='r', encoding='utf8'):
    path = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        *paths
    )
    return codecs.open(path, mode, encoding)


with open_local(['sanic_oauthlib', '__init__.py'], encoding='latin1') as fp:
    contents = fp.read()
    try:
        version = re.findall(r"^__version__ = ['\"]([^'\"]+)['\"]\r?$",
                             contents, re.M)[0]
    except IndexError:
        raise RuntimeError('Unable to determine version.')
    try:
        author = re.findall(r"^__author__ = ['\"]([^'\"]+)['\"]\r?$",
                            contents, re.M)[0]
    except IndexError:
        raise RuntimeError('Unable to determine author.')

    try:
        homepage = re.findall(r"^__homepage__ = ['\"]([^'\"]+)['\"]\r?$",
                              contents, re.M)[0]
    except IndexError:
        raise RuntimeError('Unable to determine homepage string.')


with open_local(['README.rst']) as readme:
    long_description = readme.read()


with open_local(['requirements.txt']) as req:
    install_requires = req.read().split("\n")

with open_local(['requirements-dev.txt']) as req:
    install_dev_requires = req.read().split("\n")

author, author_email = parseaddr(author)

setup(
    name='Sanic-OAuthlib',
    version=version,
    author=author,
    author_email=author_email,
    url=homepage,
    packages=[
        "sanic_oauthlib",
        "sanic_oauthlib.provider",
        "sanic_oauthlib.contrib",
    ],
    entry_points={
        'sanic_plugins':
            [
                'OAuthClient = sanic_oauthlib.client:instance',
                'OAuth1Provider = sanic_oauthlib.provider.oauth1:instance',
                'OAuth2Provider = sanic_oauthlib.provider.oauth2:instance',
            ]
    },
    description="OAuthLib for Sanic, ported from Flask-OAuthLib",
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=long_description,
    license='BSD',
    install_requires=install_requires,
    tests_require=install_dev_requires,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
