#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: authentication.py
#
# Copyright 2020 Tyfoxylos Costas, Dario Tislar, Sayantan Khanra
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Authentication code.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging
from copy import copy
from time import sleep

import requests
from requests import Session

from oktauilib.oktauilibexceptions import (ResponseError,
                                           InvalidCredentials,
                                           PushRejected,
                                           PushNotConfigured,
                                           PasswordExpired,
                                           PushTimeout,
                                           InsufficientPermissions)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''10-11-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

REQUEST_TIMEOUT = 10


class CredentialAuthenticator:  # pylint: disable=too-few-public-methods
    """Models the authenticator with a provided credentials."""

    def __init__(self, host, username, password):
        self._logger = logging.getLogger(__name__)
        self._host = host
        self._user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:82.0) Gecko/20100101 Firefox/82.0'
        self._admin_host = self.get_admin_host(host)
        self._base_url = f'https://{host}'
        self._signin_verify = f'https://{self._host}/login/login.htm'
        self.session = self._get_authenticated_session(username, password)

    def _get_authenticated_session(self, username, password):
        session = Session()
        session.headers.update({'User-Agent': self._user_agent})
        self._logger.debug('Getting initial cookies.')
        session = self._accept_initial_cookie(session)
        self._logger.debug('Getting authentication challenge.')
        session, push_response = self._get_authentication_challenge(session, username, password)
        self._logger.debug('Setting the cookie in the sessions.')
        session = self._set_state_cookie(session, push_response.state_token)
        factor = push_response.get_first_push_factor()
        if factor:
            self._signin_verify = f'https://{self._host}/signin/verify/okta/push'
            self._logger.debug('Requesting a push challenge from the user')
            session, push_response = self._push_challenge(session, factor, push_response.state_token)
            self._logger.debug('Authenticating after successful push response.')
        session = self._authenticate_after_auth(session, push_response.session_token)
        return session

    def _authenticate_after_auth(self, session, token):
        url = f'https://{self._host}/login/sessionCookieRedirect'
        params = {'checkAccountSetupComplete': True,
                  'token': token,
                  'redirectUrl': f'https://{self._host}/user/notifications'}
        headers = copy(session.headers)
        headers.update({'Referer': f'{self._signin_verify}',
                        'Host': self._host})
        response = self._handle_redirect(session, url, headers, params)
        url = response.headers.get('location')
        headers.update({'Referer': f'{self._signin_verify}',
                        'Host': self._host})
        response = self._handle_redirect(session, url, headers)
        # it ends here if user is not admin
        if response.status_code == 200:
            raise InsufficientPermissions('User is missing administrator permissions.')
        url = response.headers.get('location')
        # if not saasure do teh admin
        if 'saasure' not in url:
            headers.update({'Referer': url,
                            'Host': self._host})
            url = f'https://{self._host}/home/admin-entry'
            response = self._handle_redirect(session, url, headers)
            url = response.headers.get('location')
        # saasure
        headers.update({'Referer': f'{self._signin_verify}',
                        'Host': self._host})
        response = self._handle_redirect(session, url, headers)
        # oidc-entry
        url = response.headers.get('location')
        headers.update({'Referer': f'https://{self._host}',
                        'Host': self.get_admin_host(self._host)})
        response = self._handle_redirect(session, url, headers)
        # authorize
        url = response.headers.get('location')
        headers.update({'Referer': f'https://{self._host}',
                        'Host': self._host})
        response = self._handle_redirect(session, url, headers=headers)
        # callback
        url = response.headers.get('location')
        headers.update({'Host': self.get_admin_host(self._host)})
        headers.pop('Referer', None)
        response = self._handle_redirect(session, url, headers=headers)
        # final redirect to update session
        url = response.headers.get('location')
        headers.update({'Host': self.get_admin_host(self._host)})
        self._handle_redirect(session, url, headers=headers)
        return session

    def _handle_redirect(self, session, url, headers, params=None):
        self._logger.debug('Fetching redirect url: %s', url)
        response = session.get(url, headers=headers, params=params, allow_redirects=False)
        if not response.ok:
            self._logger.error(response.text)
            raise ResponseError('Redirect response error, authentication failed!')
        return response

    @staticmethod
    def _set_state_cookie(session, state_token):
        state_token_cookie = {'name': 'oktaStateToken',
                              'value': state_token}
        session.cookies.set(**state_token_cookie)
        return session

    def _push_challenge(self, session, factor, state_token):
        url = factor.verify_link
        if not url:
            self._logger.error('Second factor verify_link missing.')
            raise PushNotConfigured('User has PUSH enabled, but not configured.')
        params = {'autoPush': True,
                  'rememberDevice': True}
        headers = copy(session.headers)
        headers.update({'DNT': '1',
                        'Host': self._host,
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        'Referer': f'{self._signin_verify}'})
        timer = 600
        self._logger.info('Sending push challenge to the user...')
        while timer:
            try:
                self._logger.debug('Re sending push data to the backend...')
                response = session.post(url,
                                        params=params,
                                        data=json.dumps({'stateToken': state_token}),
                                        headers=headers,
                                        timeout=REQUEST_TIMEOUT)
                push_response = PushResponse(response.json())
            except requests.ConnectionError:
                pass
            if push_response.factor_result == 'REJECTED':
                raise PushRejected('Push notification rejected')
            if push_response.status == 'PASSWORD_WARN':
                raise PasswordExpired(
                    'Your Okta password is going to expire soon. Please change your Okta password before proceeding')
            if push_response.status == 'MFA_CHALLENGE':
                self._logger.info('Waiting for user to accept push challenge ... %s seconds to go', timer)
                sleep(5)
                timer = timer - 5
            elif push_response.status == 'SUCCESS':
                self._logger.info('Pushing was successfully accepted!')
                break
        else:
            raise PushTimeout('WHY GOD WHY???')
        return session, push_response

    def _accept_initial_cookie(self, session):
        url = f'{self._base_url}/login/default'
        response = session.get(url)
        if not response.ok:
            self._logger.error(response.text)
            raise ResponseError("Can't accept initial cookie")
        return session

    def _get_authentication_challenge(self, session, username, password):
        url = f'{self._base_url}/api/v1/authn'
        payload = {'options': {'warnBeforePasswordExpired': True,
                               'multiOptionalFactorEnroll': True},
                   'username': username,
                   'password': password}
        headers = copy(session.headers)
        headers.update({'DNT': '1',
                        'Host': self._host,
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'})
        response = session.post(url, data=json.dumps(payload), headers=headers)
        try:
            push_response = PushResponse(response.json())
        except ValueError:
            raise ResponseError(f'Unexpected response received {response.text}')
        error = push_response.error_summary
        if error == 'Authentication failed':  # pylint: disable=no-else-raise
            raise InvalidCredentials('invalid credentials')
        elif error:
            raise ResponseError(f'Unknown service error {error}')
        self._logger.info('Successfully authenticated user!')
        return session, push_response

    @staticmethod
    def get_admin_host(host):
        """
        Returns admin version of host url.

        Args:
            host: Okta host

        Returns:
            string of admin url

        """
        client, server, suffix = host.split('.')
        return '.'.join([f'{client}-admin', server, suffix])


class PushResponse:
    """Object modeling a response from the backend."""

    def __init__(self, data):
        self._data = data

    @property
    def error_summary(self):
        """Exposing attribute."""
        return self._data.get('errorSummary', '')

    @property
    def session_token(self):
        """Exposing attribute."""
        return self._data.get('sessionToken')

    @property
    def state_token(self):
        """Exposing attribute."""
        return self._data.get('stateToken')

    @property
    def status(self):
        """Exposing attribute."""
        return self._data.get('status')

    @property
    def factor_result(self):
        """Exposing attribute."""
        return self._data.get('factorResult')

    @property
    def cancel_link(self):
        """Exposing attribute."""
        return self._data.get('_links', {}).get('cancel', {}).get('href')

    @property
    def expires_at(self):
        """Exposing attribute."""
        return self._data.get('expiresAt')

    @property
    def factors(self):
        """Exposing attribute."""
        return [Factor(data) for data in self._data.get('_embedded', {}).get('factors', [])]

    def get_first_push_factor(self):
        """Exposing attribute."""
        return next((factor for factor in self.factors if factor.type == 'push'), None)

    def get_factors_by_type(self, type_):
        """Exposing attribute."""
        return [factor for factor in self.factors if factor.type == type_]

    def get_factors_by_provider(self, provider):
        """Exposing attribute."""
        return [factor for factor in self.factors if factor.type == provider]

    @property
    def policy(self):
        """Exposing attribute."""
        return Policy(self._data.get('_embedded', {}).get('policy', {}))

    @property
    def user(self):
        """Exposing attribute."""
        return User(self._data.get('_embedded', {}).get('user', {}))


class Factor:
    """Models the factor part of a response from the backend."""

    def __init__(self, data):
        self._data = data

    @property
    def id(self):  # pylint: disable=invalid-name
        """Exposing attribute."""
        return self._data.get('id')

    @property
    def verify_link(self):
        """Exposing attribute."""
        return self._data.get('_links', {}).get('verify', {}).get('href')

    @property
    def type(self):
        """Exposing attribute."""
        return self._data.get('factorType')

    @property
    def profile(self):
        """Exposing attribute."""
        return self._data.get('profile')

    @property
    def provider(self):
        """Exposing attribute."""
        return self._data.get('provider')

    @property
    def vendor_name(self):
        """Exposing attribute."""
        return self._data.get('vendorName')


class Policy:
    """Models the policy from a server response."""

    def __init__(self, data):
        self._data = data

    @property
    def allow_remember_device(self):
        """Exposing attribute."""
        return self._data.get('allowRememberDevice')

    @property
    def factors_policy_info(self):
        """Exposing attribute."""
        return self._data.get('factorsPolicyInfo')

    @property
    def remember_device_by_default(self):
        """Exposing attribute."""
        return self._data.get('rememberDeviceByDefault')

    @property
    def remember_device_lifetime_in_minutes(self):
        """Exposing attribute."""
        return self._data.get('rememberDeviceLifetimeInMinutes')


class User:
    """Models the User part of a response."""

    def __init__(self, data):
        self._data = data

    @property
    def id(self):  # pylint: disable=invalid-name
        """Exposing attribute."""
        return self._data.get('id')

    @property
    def password_changed_at(self):
        """Exposing attribute."""
        return self._data.get('passwordChanged')

    @property
    def first_name(self):
        """Exposing attribute."""
        return self._data.get('profile', {}).get('firstName')

    @property
    def last_name(self):
        """Exposing attribute."""
        return self._data.get('profile', {}).get('lastName')

    @property
    def locale(self):
        """Exposing attribute."""
        return self._data.get('profile', {}).get('locale')

    @property
    def login(self):
        """Exposing attribute."""
        return self._data.get('profile', {}).get('login')

    @property
    def timezone(self):
        """Exposing attribute."""
        return self._data.get('profile', {}).get('timeZone')
