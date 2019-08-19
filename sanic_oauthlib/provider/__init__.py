# coding: utf-8
"""
    sanic_oauthlib.provider
    ~~~~~~~~~~~~~~~~~~~~~~~

    Implements OAuth1 and OAuth2 providers support for Sanic.

    :copyright: (c) 2013 - 2014 by Hsiaoming Yang.
    :copyright: (c) 2019 AshleySommer.
"""

# flake8: noqa
from .oauth1 import OAuth1Provider, oauth1provider, OAuth1ProviderAssociated, OAuth1RequestValidator
from .oauth2 import OAuth2Provider, oauth2provider, OAuth2ProviderAssociated, OAuth2RequestValidator
