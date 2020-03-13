# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import unittest
import rdklibtest
from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType

RESOURCE_TYPE = 'AWS::RDS::DBInstance'
MODULE = __import__('RDS_LOGGING_ENABLED')
RULE = MODULE.RDS_LOGGING_ENABLED()

CLIENT_FACTORY = MagicMock()
RDS_CLIENT_MOCK = MagicMock()


def mock_get_client(client_name, *args, **kwargs):
    if client_name == 'rds':
        return RDS_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")


@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    all_logs_enabled_compliant = {
        "configuration": {
            "enabledCloudwatchLogsExports": ["postgresql", "upgrade"],
            "engine": "postgres"
        }
    }
    no_logs_enabled_non_compliant = {
        "configuration": {
            "enabledCloudwatchLogsExports": [],
            "engine": "postgres"
        }
    }
    one_log_enabled_non_compliant = {
        "configuration": {
            "enabledCloudwatchLogsExports": ["error"],
            "engine": "aurora"
        }
    }

    def test_scenario1_evaluatechange_alllogsenabledonrds_returnscompliant(self):
        response = RULE.evaluate_change(None, CLIENT_FACTORY, self.all_logs_enabled_compliant, None)
        resp_expected = [Evaluation(ComplianceType.COMPLIANT)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario2_evaluatechange_nologsenabledonrds_returnsnoncompliant(self):
        response = RULE.evaluate_change(None, CLIENT_FACTORY, self.no_logs_enabled_non_compliant, None)
        resp_expected = [Evaluation(ComplianceType.NON_COMPLIANT,
                                    annotation="['postgresql', 'upgrade'] logs are not enabled")]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario2_evaluatechange_onetypeoflogisenabledonrds_returnsnoncompliant(self):
        response = RULE.evaluate_change(None, CLIENT_FACTORY, self.one_log_enabled_non_compliant, None)
        resp_expected = [Evaluation(ComplianceType.NON_COMPLIANT,
                                    annotation="['audit', 'general', 'slowquery'] logs are not enabled")]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
