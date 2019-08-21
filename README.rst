Sanic-OAuthlib
==============

.. image:: https://img.shields.io/pypi/wheel/sanic-oauthlib.svg
   :target: https://pypi.python.org/pypi/sanic-OAuthlib/
   :alt: Wheel Status
.. image:: https://img.shields.io/pypi/v/sanic-oauthlib.svg
   :target: https://pypi.python.org/pypi/sanic-oauthlib/
   :alt: Latest Version
.. image:: https://travis-ci.org/ashleysommer/sanic-oauthlib.svg?branch=master
   :target: https://travis-ci.org/ashleysommer/sanic-oauthlib
   :alt: Travis CI Status
.. image:: https://coveralls.io/repos/ashleysommer/sanic-oauthlib/badge.svg?branch=master
   :target: https://coveralls.io/r/ashleysommer/sanic-oauthlib
   :alt: Coverage Status

=====

Sanic-OAuthlib is an extension to Sanic that allows you to interact with
remote OAuth enabled applications. On the client site, it is a replacement
for Sanic-OAuth. But it does more than that, it also helps you to create
OAuth providers.

Sanic-OAuthlib is a fork of Flask-OAuthlib, ported to sanic using the
SanicPluginsFramework.

Sanic-OAuthlib relies on oauthlib_.

.. _oauthlib: https://github.com/idan/oauthlib


Features
--------
(These features are directly ported from Flask-OAuthLib)

- Support for OAuth 1.0a, 1.0, 1.1, OAuth2 client
- Friendly API (same as Sanic-OAuth)
- Direct integration with Sanic using SanicPluginsFramework
- Basic support for remote method invocation of RESTful APIs
- Support OAuth1 provider with HMAC and RSA signature
- Support OAuth2 provider with Bearer token

And request more features at `github issues`_.

.. _`github issues`: https://github.com/ashleysommer/sanic-oauthlib/issues


Security Reporting
------------------

If you found security bugs which can not be public, send me email at `ashleysommer@gmail.com`.
Attachment with patch is welcome.


Installation
------------

Installing sanic-oauthlib is simple with pip_::

    $ pip install Sanic-OAuthlib

If you don't have pip installed, try with easy_install::

    $ easy_install Sanic-OAuthlib

.. _pip: http://www.pip-installer.org/


Additional Notes
----------------

See the original documentation for Flask-OAuthlib here: `flask-oauthlib@readthedocs`_.

.. _`flask-oauthlib@readthedocs`: https://flask-oauthlib.readthedocs.io

If you are only interested in the client part, you can find some examples
in the ``example`` directory.

There is also a `development version <https://github.com/lepture/flask-oauthlib/archive/master.zip#egg=Flask-OAuthlib-dev>`_ on GitHub.
