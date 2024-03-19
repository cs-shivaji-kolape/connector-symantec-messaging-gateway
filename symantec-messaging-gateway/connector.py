"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import SMG

logger = get_logger('symantec-messaging-gateway')


class SymantecMessagingGateway(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info('executing action {}'.format(operation))
            smg = SMG(config)
            operations = {
                'blacklist_email': smg.blacklist_email,
                'unblacklist_email': smg.unblacklist_email,
                'blacklist_domain': smg.blacklist_domain,
                'unblacklist_domain': smg.unblacklist_domain,
                'blacklist_ip': smg.blacklist_ip,
                'unblacklist_ip': smg.unblacklist_ip,
                'audit_logs_search': smg.audit_logs_search,
                'advanced_audit_logs_search': smg.advanced_audit_logs_search
            }
            action = operations.get(operation)
            return action(config, params)
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def check_health(self, config):
        try:
            logger.info('executing check health')
            smg = SMG(config)
            connection_response = smg.test_connection(config)
            return connection_response
        except Exception as exp:
            logger.exception(str(exp))
            raise ConnectorError(str(exp))
