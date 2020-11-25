#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: oktauilib.py
#
# Copyright 2020 Costas Tyfoxylos
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
Main code for oktauilib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import json
import logging

from bs4 import BeautifulSoup as Bfs
from oktauilib.oktauilibexceptions import (ResponseError,
                                           AuthenticationExpired)
from oktauilib.authentication import CredentialAuthenticator
from .helpers import (ADUser,
                      OktaUser,
                      OktaUserType,
                      UsersDataStructure)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''10-11-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''oktauilib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())
AWS_APPLICATION_URL_COMPONENT = 'admin/app/amazon_aws/instance/'


class OktaUI:  # pylint: disable=too-many-instance-attributes
    """Object authenticating with okta admin backend through push mechanism."""

    def __init__(self, host, username, password):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        if not all([arg is not None for arg in [host, username, password]]):
            self._logger.error('Empty argument passed!')
            raise ValueError('Empty argument passed!')
        self._host = host
        self._user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0'
        self._admin_host = CredentialAuthenticator.get_admin_host(host)
        self._base_url = f'https://{host}'
        self.session = self._authenticate_session(self._host, username, password)
        self._admin_aws_application_url = f'https://{self._admin_host}/{AWS_APPLICATION_URL_COMPONENT}'
        self._admin_group = f'https://{self._admin_host}/admin/group'
        self._admin_user = f'https://{self._admin_host}/admin/user'
        self._api_internal = f'https://{self._admin_host}/api/internal'
        self._api_users = f'https://{self._admin_host}/api/v1/users'
        self._active_directory_instance = f'https://{self._admin_host}/admin/app/active_directory/instance'

    @staticmethod
    def _authenticate_session(host, username, password):
        authentication = CredentialAuthenticator(host, username, password)
        return authentication.session

    @staticmethod
    def _parse_xsrf_token(response):
        soup = Bfs(response.text, features='html.parser')
        xsrf = soup.find('span', id='_xsrfToken')
        if not xsrf:
            if 'Sign In</title>' in response.text:
                raise AuthenticationExpired()
            raise ResponseError(f'Unable to get xsrf token from page, response was :{response.text}')
        return xsrf.string.strip()

    def _get_xsrf_token(self):
        response = self.session.get(f'https://{self._admin_host}/admin/dashboard')
        if response.ok:
            return self._parse_xsrf_token(response)
        raise ResponseError(response.text)

    def _get_group_xsrf_token(self, group_id):
        group_headers = {'Host': self._admin_host,
                         'Referer': f'https://{self._admin_host}/admin/groups',
                         'User-Agent': self._user_agent}
        group_url = f'{self._admin_group}/{group_id}'
        group_response = self.session.get(group_url, headers=group_headers)
        return self._parse_xsrf_token(group_response)

    @property
    def directories(self):
        """Return list of directories."""
        url = f'https://{self._admin_host}/admin/people/directories'
        response = self.session.get(url)
        if not response.ok:
            self._logger.error(response.text)
            return []
        soup = Bfs(response.text, features='html.parser')
        xsrf = self._parse_xsrf_token(response)
        return [ActiveDirectory(self, data, xsrf) for data in soup.find_all('p', {'class': 'active_directory'})]

    @property
    def _request_headers(self):
        """Return needed request headers."""
        return {'X-Okta-XsrfToken': self._get_xsrf_token(),
                'X-Requested-With': 'XMLHttpRequest'}

    def get_directory_by_name(self, name):
        """Return directory matched by name."""
        return next((directory for directory in self.directories if directory.name == name), None)

    @staticmethod
    def parse_response(text):
        """Returns JSON part of mixed response."""
        return json.loads(text.split(';')[1])

    def get_aws_provisioning_data(self, application_id):
        """Gets the provisioning data for okta aws application.

        Args:
            application_id: Okta application id

        Returns:
            account_ids: Account ids associated with the application
            xsrfToken: xsrf token associated with the application

        """
        url = f'{self._admin_aws_application_url}/{application_id}/settings/user-mgmt'
        response = self.session.get(url)
        soup = Bfs(response.text, 'html.parser')
        user_mgmt_account_ids = soup.find('input', {'id': 'userMgmtSettings.accountsIds'})
        account_ids = user_mgmt_account_ids.get('value', '') if user_mgmt_account_ids else ''
        user_mgmt_xsrftoken = soup.find('input', {'name': '_xsrfToken'})
        xsrftoken = user_mgmt_xsrftoken.get('value', '') if user_mgmt_xsrftoken else ''
        return account_ids, xsrftoken

    def set_aws_provisioning_data(self, application_id, account_ids):
        """Saves the provisioning data for okta aws application.

        Args:
            application_id: Okta application id
            account_ids: the list of account ids which need to be added

        Returns:
            response: Response of the post method

        """
        existing_account_ids, xsrftoken = self.get_aws_provisioning_data(application_id)
        if not all([existing_account_ids, xsrftoken]):
            self._logger.error('Could not retrieve account_id list or xsrftoken from okta configuration')
            return False
        url = f'{self._admin_aws_application_url}/{application_id}/settings/user-mgmt'
        headers = {
            'referer': f'{self._admin_aws_application_url}/{application_id}/',
            'x-okta-xsrftoken': xsrftoken,
            'x-requested-with': 'XMLHttpRequest',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': self._admin_host}
        final_account_ids = f"{existing_account_ids},{','.join(account_ids)}"
        response = self.session.post(url, data={'accountsIds': final_account_ids,
                                                'pushNewAccount': 'true'}, headers=headers)
        if not response.ok:
            self._logger.error('Error posting, response: %s', response.text)
        return response.ok

    def push_group(self,  # pylint: disable=too-many-arguments
                   group_id,
                   group_name,
                   directory_id,
                   directory_label,
                   status='ACTIVE',
                   scope='DOMAIN LOCAL',
                   group_type='SECURITY'):
        """Pushes a group to an active directory through okta."""
        xsrf = self._get_group_xsrf_token(group_id)
        url = f'{self._api_internal}/instance/{directory_id}/grouppush'
        referer = f'{self._active_directory_instance}/{directory_id}'
        headers = {'Referer': referer,
                   'X-Okta-XsrfToken': xsrf,
                   'X-Requested-With': 'XMLHttpRequest',
                   'Content-Type': 'application/json',
                   'Host': self._admin_host,
                   'Origin': f'https://{self._admin_host}',
                   'User-Agent': self._user_agent}
        payload = {'status': status,
                   'userGroupId': group_id,
                   'groupPushAttributes': {'groupScope': scope,
                                           'groupType': group_type,
                                           'distinguishedName':
                                               f"ou=groups,ou=ad,dc={',dc='.join(directory_label.split('.'))}",
                                           'samAccountName': group_name}}
        self._logger.debug('Pushing group to url %s with payload %s', url, payload)
        response = self.session.post(url, data=json.dumps(payload), headers=headers)
        if not response.ok:
            self._logger.error('Error posting, response: %s', response.text)
        return response.ok

    def _get_working_set_id(self, group_id):
        """Returns workingSetId from workingSetApps endpoint."""
        xsrf = self._get_group_xsrf_token(group_id)
        url = f'{self._admin_group}/{group_id}/workingSetApps'
        referer = f'{self._admin_group}/{group_id}'
        headers = {'Referer': referer,
                   'X-Okta-XsrfToken': xsrf,
                   'X-Requested-With': 'XMLHttpRequest',
                   'Content-Type': 'application/json',
                   'Host': self._admin_host,
                   'Origin': f'https://{self._admin_host}',
                   'User-Agent': self._user_agent}
        response = self.session.post(url, data=json.dumps({}), headers=headers)
        try:
            data = json.loads(response.text.split(';')[1])
        except (ValueError, TypeError, AttributeError):
            raise ResponseError(f'Can not retrieve data for working set id, invalid response received, {response.text}')
        working_set_id = data.get('workingSetId')
        if not working_set_id:
            raise ResponseError(f'Unable to get the working set id, response received was {response.text}')
        return working_set_id

    def push_users(self, group_id, directory_id, directory_label):
        """Pushes users to an active directory."""
        working_set_id = self._get_working_set_id(group_id)
        xsrf = self._get_group_xsrf_token(group_id)
        url = f'{self._admin_group}/{group_id}/submitApps'
        referer = f'{self._admin_group}/{group_id}/workingSetApps/{working_set_id}/directories'
        headers = {'Referer': referer,
                   'X-Okta-XsrfToken': xsrf,
                   'X-Requested-With': 'XMLHttpRequest',
                   'Content-Type': 'application/json',
                   'Host': self._admin_host,
                   'Origin': f'https://{self._admin_host}',
                   'User-Agent': self._user_agent}
        payload = {'assignments': {directory_id: {'extensibleProfile[adCountryCode]': '',
                                                  'extensibleProfile[co]': '',
                                                  'extensibleProfile[description]': '',
                                                  'extensibleProfile[division]': '',
                                                  'extensibleProfile[facsimileTelephoneNumber]': '',
                                                  'extensibleProfile[honorificPrefix]': '',
                                                  'extensibleProfile[honorificSuffix]': '',
                                                  'extensibleProfile[preferredLanguage]': '',
                                                  'organizationalUnit':
                                                      f"ou=users,ou=ad,dc={',dc='.join(directory_label.split('.'))}",
                                                  'workingSetId': {working_set_id: None},
                                                  'appInstanceIdsToRemove': {}}}}
        self._logger.debug('Pushing users to url %s with payload %s', url, payload)
        response = self.session.post(url, data=json.dumps(payload), headers=headers)
        if not response.ok:
            self._logger.error('Error posting, response: %s', response.text)
        return response.ok

    def user_exists(self, login):
        """Checks if user exists."""
        url = f'{self._api_internal}/people?search={login}'
        response = self.session.get(url)
        if not response.ok:
            self._logger.error(response.text)
            return False
        return next(
            (True for person in response.json().get('personList')
             if person.get('login') == login),
            False)

    def user_types(self):
        """List of user types."""
        url = f'{self._api_users}/types'
        response = self.session.get(url)
        if not response.ok:
            self._logger.error(response.text)
            yield from ()
        for user_type in response.json():
            yield OktaUserType(user_type)

    def get_user_by_login(self, login):
        """Return User object by login.

        Args:
            login: User login

        """
        url = f'{self._api_internal}/people?search={login}'
        response = self.session.get(url)
        if not response.ok:
            self._logger.error(response.text)
            return None
        return next(
            (OktaUser(user) for user in response.json().get('personList') if user.get('login') == login),
            None)

    def create_user(self, login, password,
                    first_name='TempFirstName', last_name='TempLastName', user_type: OktaUserType = None):
        # pylint: disable=too-many-arguments
        """Returns OktaUser.

        Args:
            login: users login (email)
            password: password
            first_name: users first name
            last_name: users last name
            user_type: Okta user type

        Returns: Okta user

        """
        if self.user_exists(login):
            self._logger.error("Can't continue, user %s already exists", login)
            return None
        # get default user type if not provided
        if not user_type or not isinstance(user_type, OktaUserType):
            user_type = next((user_type for user_type in self.user_types() if user_type.is_default),
                             None)
            if not user_type:
                self._logger.error('Default user type not found!')
                return None
        # create user
        temp_user = {'type': {'id': user_type.id},
                     'profile': {'login': login,
                                 'email': login,
                                 'firstName': first_name,
                                 'lastName': last_name},
                     'credentials': {'password': {'value': password}}}
        url = f'{self._api_users}?activate=true'
        response = self.session.post(url, json=temp_user, headers=self._request_headers)
        if not response.ok:
            self._logger.error('User %s not created', login)
            self._logger.error(response.text)
            return None
        self._logger.info('User created with id: %s', response.json().get('id'))
        return OktaUser(response.json())

    def deactivate_user(self, login):
        """
        Deactivates user in Okta.

        Args:
            login: users login (email)

        Returns: True if deactivation succeeded, otherwise False.

        """
        data = {'sendEmail': 'false'}
        user = self.get_user_by_login(login)
        if not user:
            self._logger.error('User %s not found!', login)
            return False
        if user.status_code == 'INACTIVE':
            self._logger.info('User %s already deactivated, skipping!', login)
            return True
        url = f'{self._admin_user}/deactivate/{user.id}'
        response = self.session.post(url, data=data, headers=self._request_headers)
        if not response.ok:
            self._logger.error(response.text)
            return False
        self._logger.info('User %s deactivated!', user.login)
        return True

    def delete_user(self, login):
        """
        Deletes user.

        Args:
            login: users login (email)

        Returns: True/False

        """
        user = self.get_user_by_login(login)
        if not user:
            self._logger.error('User %s not found!', login)
            return False
        if user.status_code != 'INACTIVE':
            self._logger.error('User %s not deactivated, aborting delete', login)
            return False
        url = f'{self._api_users}/{user.id}'
        response = self.session.delete(url, headers=self._request_headers)
        if not response.ok:
            self._logger.error("Can't delete user %s", login)
            self._logger.error(response.text)
            return False
        self._logger.info('User %s deleted', user.login)
        return True


class ActiveDirectory:
    """Active directory object from Okta UI."""

    def __init__(self, okta_instance, html_data, xsrf_token):
        self.okta = okta_instance
        self.id, self.name = self._parse(html_data)  # pylint: disable=invalid-name
        self.xsrf_token = xsrf_token

    @staticmethod
    def _users_query_params(login_name):
        return {'sEcho': '8',
                'iColumns': '7',
                'sColumns': 'id,conflict,conflictMessage,ignored,user,actions,checked',
                'iDisplayStart': '0',
                'iDisplayLength': '10',
                'sSearch': login_name,
                'bRegex': 'false',
                'sSearch_0': '',
                'bRegex_0': 'false',
                'bSearchable_0': 'true',
                'sSearch_1': '',
                'bRegex_1': 'false',
                'bSearchable_1': 'true',
                'sSearch_2': '',
                'bRegex_2': 'false',
                'bSearchable_2': 'true',
                'sSearch_3': '',
                'bRegex_3': 'false',
                'bSearchable_3': 'true',
                'sSearch_4': '',
                'bRegex_4': 'false',
                'bSearchable_4': 'true',
                'sSearch_5': '',
                'bRegex_5': 'false',
                'bSearchable_5': 'true',
                'sSearch_6': '',
                'bRegex_6': 'false',
                'bSearchable_6': 'true',
                'iSortingCols': '1',
                'iSortCol_0': '0',
                'sSortDir_0': 'asc',
                'bSortable_0': 'true',
                'bSortable_1': 'true',
                'bSortable_2': 'true',
                'bSortable_3': 'true',
                'bSortable_4': 'false',
                'bSortable_5': 'false',
                'bSortable_6': 'false',
                'matchTypes': 'NONE,EXACT,PARTIAL',
                'ignoredIncluded': 'false'}

    @staticmethod
    def _parse(html_data):
        """Parses HTML data response."""
        _, _, id_ = html_data.attrs.get('id').partition('-')
        name = html_data.text.strip()
        return id_, name

    def is_user_unassigned(self, email):
        """Checks if user is unassigned."""
        return bool(self.get_unassigned_user_by_email(email))

    def get_unassigned_user_by_email(self, email):
        """
        Gets unassigned user by username.

        Args:
            email: users email

        Returns: ADUser model.

        """
        url = f'{self.okta._active_directory_instance}/{self.id}/users/unassigned'  # pylint: disable=protected-access
        params = self._users_query_params(email)
        response = self.okta.session.get(url, params=params, headers=self.okta._request_headers)  # pylint: disable=protected-access
        if not response.ok:
            self.okta._logger.error(response.text)  # pylint: disable=protected-access
            return None

        data = [UsersDataStructure(*data) for data in self.okta.parse_response(response.text).get('aaData')]
        return next((ADUser(user) for user in data if ADUser(user).email == email), None)

    def import_users(self, partial=True):
        """
        Imports users from AD to Okta.

        Args:
            partial: Bool if it should use partial import
        Returns: ImportJob object

        """
        url = f'{self.okta._admin_user}/import/active_directory/{self.id}/start'  # pylint: disable=protected-access
        data = {'_xsrfToken': self.xsrf_token,
                'fullImport': 'false' if partial else 'true'}
        headers = self.okta._request_headers  # pylint: disable=protected-access
        headers.update({'Referer': f'{self.okta._active_directory_instance}/{self.id}/',  # pylint: disable=protected-access
                        'Host': self.okta._admin_host,  # pylint: disable=protected-access
                        'Origin': f'https://{self.okta._admin_host}',  # pylint: disable=protected-access
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
        response = self.okta.session.post(url, data=data, headers=headers)
        if not response.ok:
            self.okta._logger.error(response.text)  # pylint: disable=protected-access
            return None
        return ImportJob(self.okta, self.okta.parse_response(response.text))

    def set_current_user_assignment(self, ad_user: ADUser, assignment_action):
        """
        Sets current user assignment to provided assignment action.

        Args:
            ad_user: Active Directory user object
            assignment_action: Action to be set

        Returns: Bool

        """
        assignment = next((assignment for assignment in ad_user.assignments if assignment.action == assignment_action),
                          None)
        if not assignment:
            self.okta._logger.error(f'Assignment {assignment_action} not found for user {ad_user.user_name}')  # pylint: disable=protected-access
            return False
        if assignment.current:
            self.okta._logger.debug(f'Assignment {assignment_action} already set for user {ad_user.user_name}')  # pylint: disable=protected-access
            return True
        data = {'_xsrfToken': self.xsrf_token,
                'action': assignment_action,
                'assignedId': assignment.user_id if assignment.user_id else '',
                'manualAssignUser': False}
        # pylint: disable=protected-access
        url = f'{self.okta._active_directory_instance}/{self.id}/users/{ad_user.id}/action'
        headers = self.okta._request_headers
        headers.update({'Referer': f'{self.okta._active_directory_instance}/{self.id}/',
                        'Host': self.okta._admin_host,
                        'Origin': f'https://{self.okta._admin_host}',
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
        response = self.okta.session.post(url, data=data, headers=headers)
        if not response.ok:
            # pylint: disable=protected-access
            self.okta._logger.error(f"Can't set {assignment_action} assignment for {ad_user.user_name}")
            self.okta._logger.error(response.text)
            return False
        return True

    def confirm_user_assignment(self, ad_user: ADUser, enable_auto_activation=True):
        """
        Confirms user assignment.

        Args:
            ad_user: Active Directory user object
            enable_auto_activation: Enable auto activation

        Returns: Bool if confirmation succeeds

        """
        data = {'_xsrfToken': self.xsrf_token,
                'confirmIds': ad_user.id,
                'enableAutoactivation': enable_auto_activation}
        # pylint: disable=protected-access
        url = f'{self.okta._active_directory_instance}/{self.id}/users/confirm'
        headers = self.okta._request_headers
        headers.update({'Referer': f'{self.okta._active_directory_instance}/{self.id}/',
                        'Host': self.okta._admin_host,
                        'Origin': f'https://{self.okta._admin_host}',
                        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
        response = self.okta.session.post(url, data=data, headers=headers)
        if not response.ok:
            self.okta._logger.error(response.text)  # pylint: disable=protected-access
            return False
        return True

    def create_okta_user_for_ad_user(self, ad_user: ADUser):
        """Creates new Okta user for AD user assignment.

        Args:
            ad_user: Object of ADUser

        Returns: assignment

        """
        if not next((assignment.current for assignment in ad_user.assignments if assignment.action == 'CREATE'),
                    False):
            if not self.set_current_user_assignment(ad_user, 'CREATE'):
                # pylint: disable=protected-access
                self.okta._logger.error(f'User assignment for {ad_user.user_name} not set!')
                return False
        return self.confirm_user_assignment(ad_user)

    @property
    def _counters(self):
        """Returns counters from users/counts endpoint."""
        # pylint: disable=protected-access
        url = f'{self.okta._active_directory_instance}/{self.id}/users/counts'
        response = self.okta.session.get(url, headers=self.okta._request_headers)  # pylint: disable=protected-access
        if not response.ok:
            self.okta._logger.error(response.text)  # pylint: disable=protected-access
            return {}
        return self.okta.parse_response(response.text)

    @property
    def unassigned_count(self):
        """Returns unassigned count."""
        return self._counters.get('unassignedCount')

    @property
    def assigned_count(self):
        """Returns assigned count."""
        return self._counters.get('assignedCount')


class ImportJob:
    """Models Import Job object."""

    def __init__(self, okta_instance, data):
        self.okta = okta_instance
        self.id = data.get('modelMap', {}).get('jobId')  # pylint: disable=invalid-name
        self._data = None
        self._update()
        print(self._data.get('status'))
        self._is_running = True

    def _update(self):
        url = f'https://{self.okta._admin_host}/joblist/status'  # pylint: disable=protected-access
        params = {'jobs': self.id}
        response = self.okta.session.get(url, params=params)
        if response.ok:
            self._data = self.okta.parse_response(response.text).get('jobList').get('jobList')[0]
            self._is_running = self._data.get('status') in ['IN_PROGRESS', 'CREATED']
        else:
            self.okta._logger.error(response.text)  # pylint: disable=protected-access

    @property
    def is_running(self):
        """Return running state."""
        if self._is_running:
            self._update()
        return self._is_running

    @property
    def message(self):
        """Returns localized message."""
        if self._is_running:
            self._update()
        return self._data.get('localizedMessage')

    @property
    def status(self):
        """Return current status."""
        if self._is_running:
            self._update()
        return self._data.get('status')

    @property
    def status_text(self):
        """Returns current status info text."""
        if self._is_running:
            self._update()
        return self._data.get('statusText')

    @property
    def percentage_done(self):
        """Returns percentage done."""
        if self._is_running:
            self._update()
        return self._data.get('currentStep')
