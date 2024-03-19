"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import requests
import arrow
import re
import json
import time
import csv
import string
from io import StringIO
from bs4 import BeautifulSoup
from requests_toolbelt.utils import dump
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('symantec-messaging-gateway')
SENDER_GRP = 'reputation/sender-group/'
AUDIT_LOGS = 'status/message-audit/MessageAuditFlow'
AUDIT_LOGS_CSV = 'status/message-audit/MessageAuditFlow$export.flo?no-cache=true'
VIEW_SENDER_GRP = SENDER_GRP + 'viewSenderGroup.do'

filter_map = {
    "Sender": "SENDER",
    "Recipient": "RCPTS",
    "Subject": "SUBJECT",
    "Audit ID": "AUDIT_UID",
    "Connection IP": "ACCEPT",
    "Logical IP": "LOGICAL_IP"
}


# utilities
def csv_to_json(csv_data, ignore_none_ascii):
    json_array = []
    if ignore_none_ascii:
        csv_data = ''.join(filter(lambda x: x in set(string.printable), csv_data))

    reader = csv.DictReader(StringIO(csv_data), delimiter=';')
    for row in reader:
        logger.debug('Adding row: {}'.format(row))
        json_array.append(row)
    return json.loads(json.dumps(json_array))


def html_to_json(content):
    table_data = []
    table_headers = []
    soup = BeautifulSoup(content, "html.parser")
    tab = soup.find("table", {"class": "table"})
    rows = tab.find_all("tr")
    for tr_index, row in enumerate(rows):
        cells = row.find_all("td")
        items = {}
        link = ''
        js_text = ''
        for td_index, cell in enumerate(cells):
            if tr_index == 0:
                table_headers.append(cell.text.strip())
            else:
                links = cell.find_all("a", href=True)
                cell_content = cell.text.strip()
                logger.debug('Parsed HTML table cell Content: {}'.format(cell_content))
                script = cell.find("script")
                if script and len(script) > 0:
                    js_text = re.search(r"'([^']*)'", script.text).group(1)
                    logger.debug('Parsed HTML table cell JS Script: {}'.format(js_text))
                if links and len(links) > 0:
                    link = links[0]['href']
                    audit_uid = re.search(r'[0-9a-fA-F]{8}\-[0-9a-fA-F]{16}\-[0-9a-fA-F]{2}\-[0-9a-fA-F]{12}',
                                          link).group()
                    items.update({'auditUID': audit_uid})
                    logger.debug('Parsed HTML table cell Audit UUID: {}'.format(audit_uid))

                items.update({table_headers[td_index]: cell_content if len(cell_content) > 0 else js_text})
        if items:
            table_data.append(items)

    return table_data


def build_search_payload(params):
    ''' builds requests payload for the search actions '''
    filters = {
        'hostFilterId': '0',
        'optionalFilterId1': 'none',
        'optionalFilterValue1': '',
        'optionalFilterId2': 'none',
        'optionalFilterValue2': '',
        'optionalFilterId3': 'none',
        'optionalFilterValue3': '',
        'timeRange': 'timeRange.customize',
        'encodingSelected': 'UTF-8',
        'delimiterSelected': '0x003b',
        # Using ";" instead of "," to prevent parsing errors should the data contain extra commas
    }
    for k, v in params.items():
        if 'start_time' in k:
            start_time = arrow.get(v)
            filters.update({"startDate": start_time.format("MM/DD/YY")})
            filters.update({"startHourSelected": start_time.format("HH")})
            filters.update({"startMinuteSelected": start_time.format("mm")})

        elif 'end_time' in k:
            end_time = arrow.get(v)
            filters.update({"endDate": end_time.format("MM/DD/YY")})
            filters.update({"endHourSelected": end_time.format("HH")})
            filters.update({"endMinuteSelected": end_time.format("mm")})

        elif 'mandatoryFilterId' in k:
            filters.update({k: filter_map[v]})

        else:
            filters.update({k: v})
    return filters


class SMG:

    def __init__(self, config):
        self._session = requests.Session()
        self.verify_ssl = config.get("verify_ssl", False)
        base_url = config.get('base_url').strip('/') + '/brightmail/'
        if not base_url.startswith('https://'):
            base_url = 'https://' + base_url
        self.base_url = base_url

    def _make_request(self, endpoint, method='get', params=None, data=None, headers=None):
        try:
            url = self.base_url + endpoint
            logger.info('Executing url {}'.format(url))
            call_method = getattr(self._session, method)
            response = call_method(url, params=params, data=data, headers=headers, verify=self.verify_ssl)
            if method in ['post']:
                logger.debug('\nreq data:\n{0}\n'.format(dump.dump_all(response).decode('utf-8')))
            if response.ok or response.status_code == 302:
                logger.info('successfully get response for url {}'.format(url))
                return response
            elif response.status_code == 401:
                raise ConnectorError('Invalid endpoint or credentials')
            elif response.status_code == 403:
                raise ConnectorError('Unauthorized')
            elif response.status_code == 404:
                raise ConnectorError('URL not found')
            else:
                logger.error(response.content)
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(response.content))

    def _login(self, config):
        try:
            resp = self._make_request('viewLogin.do', method='get')
            soup_obj = BeautifulSoup(resp.text, 'html.parser')
            lastlogin_tag = soup_obj.find('input', {'name': 'lastlogin'})
            if not lastlogin_tag:
                logger.error('Login failed, not able to find last login time in viewLogin response')
                raise ConnectorError('Login failed, not able to find last login time')
            lastlogin = lastlogin_tag['value']
            params = {'lastlogin': lastlogin,
                      'username': config['user_name'],
                      'password': config['password']}
            resp = self._make_request('/login.do', params=params)
            soup_obj = BeautifulSoup(resp.text, 'html.parser')
            token_tag = soup_obj.find('input', {'name': 'symantec.brightmail.key.TOKEN'})
            if not token_tag:
                logger.error('Login failed, Could not find token in login response')
                raise ConnectorError('Login failed, invalid input credentials')
            token = token_tag['value']
            logger.info('login successfully')
            return token
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def _is_exists(self, input, resp):
        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
            member_table = soup.find('table', {'id': 'membersList'})
            if not member_table:
                logger.error('Not able to find member list table')
                raise ConnectorError('Not able to find member list table')
            item_id = None
            member_tags = soup.findAll('tr')
            if not member_tags:
                logger.error('No items found in bad senders list')
                raise ConnectorError('No items found in bad senders list')
            for tag in member_tags:
                if input in tag.text:
                    checkbox = tag.find('input', {'name': 'selectedGroupMembers'})
                    if not checkbox:
                        logger.error('Item ID not for input {}'.format(input))
                        raise ConnectorError('Item ID not for input {}'.format(input))
                    item_id = checkbox['value']
                    break
            return item_id
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def _blacklist_item(self, config, input, sender_group):
        try:
            token = self._login(config)
            resp = self._make_request(VIEW_SENDER_GRP + '?view=badSenders')
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders',
                'selectedSenderGroups': sender_group
            }
            resp = self._make_request(VIEW_SENDER_GRP, params=params)
            resp = self._make_request(SENDER_GRP + 'addSender.do', params=params)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'addEditSenders': input,
                'view': 'badSenders'
            }
            resp = self._make_request(SENDER_GRP + 'saveSender.do', params=params)
            # Look for the error message
            soup = BeautifulSoup(resp.content, 'html.parser')
            error = soup.find('div', 'errorMessageText')
            if error:
                error_message = ' '.join(error.text.split())  # Removes whitespaces from string
                logger.error(error_message)
                raise ConnectorError(error_message)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders'
            }
            resp = self._make_request(SENDER_GRP + 'saveGroup.do', params=params)
            if resp.ok:
                return 'Successfully blacklisted {}'.format(input)
            logger.error(resp.content)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
        raise ConnectorError(resp.content)

    def _unblacklist_item(self, config, input, sender_group):
        try:
            token = self._login(config)
            resp = self._make_request(VIEW_SENDER_GRP + '?view=badSenders')
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders',
                'selectedSenderGroups': sender_group
            }
            resp = self._make_request(VIEW_SENDER_GRP, params=params)
            item_id = self._is_exists(input, resp)
            if not item_id:
                logger.error('Input not found in blacklist')
                raise ConnectorError('Input not found in blacklist')
            resp = self._make_request(SENDER_GRP + 'addSender.do', params=params)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'selectedGroupMembers': item_id,
                'view': 'badSenders',
                'selectedSenderGroups': sender_group
            }
            resp = self._make_request(SENDER_GRP + 'deleteSender.do', params=params)
            params = {
                'symantec.brightmail.key.TOKEN': token,
                'view': 'badSenders'
            }
            resp = self._make_request(SENDER_GRP + 'saveGroup.do', params=params)
            if resp.ok:
                return 'Successfully remove {} from blacklist'.format(input)
            logger.error(resp.content)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
        raise ConnectorError(resp.content)

    def blacklist_email(self, config, params):
        return self._blacklist_item(config, params.get('email_id', None), '1|3')

    def unblacklist_email(self, config, params):
        return self._unblacklist_item(config, params.get('email_id', None), '1|3')

    def blacklist_domain(self, config, params):
        return self._blacklist_item(config, params.get('domain', None), '1|3')

    def unblacklist_domain(self, config, params):
        return self._unblacklist_item(config, params.get('domain', None), '1|3')

    def blacklist_ip(self, config, params):
        return self._blacklist_item(config, params.get('ip', None), '1|1')

    def unblacklist_ip(self, config, params):
        return self._unblacklist_item(config, params.get('ip', None), '1|1')

    def test_connection(self, config):
        return self._login(config)

    def audit_logs_search(self, config, params):
        ''' Searches the logs and converts the html output to JSON '''
        try:
            search_params = build_search_payload(params)
            token = self._login(config)
            search_params.update({'symantec.brightmail.key.TOKEN': token})
            if params.get('entriesPerPage'):
                endpoint = AUDIT_LOGS + '$changeEntriesPerPage.flo'
                response = self._make_request(endpoint, 'post', params=search_params)
            endpoint = AUDIT_LOGS + '$search.flo'
            resp = self._make_request(endpoint, 'post', data=search_params)
            if params.get('pageNumber') and params.get('pageNumber') > 1:
                endpoint = AUDIT_LOGS + '$gotoPage.flo'
                resp = self._make_request(endpoint, 'post', params=search_params)
            json_response = html_to_json(resp.text)
            logger.debug(json.dumps(json_response, indent=3))
            return html_to_json(resp.text)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def advanced_audit_logs_search(self, config, params):
        ''' Exports the logs and converts the csv output to JSON '''
        try:
            ignore_none_ascii = params.get('remove_none_ascii', True)
            search_params = build_search_payload(params)
            token = self._login(config)
            search_params.update({'symantec.brightmail.key.TOKEN': token})
            self._make_request(AUDIT_LOGS + '$search.flo', 'post', params=search_params)
            time.sleep(1)
            resp = self._make_request(AUDIT_LOGS_CSV, 'post', params=search_params)
            events_json = csv_to_json(resp.text, ignore_none_ascii)
            logger.debug('Received events: {0}'.format(events_json))
            return events_json

        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))
