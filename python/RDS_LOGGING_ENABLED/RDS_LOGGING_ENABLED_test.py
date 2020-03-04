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
from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::RDS::DBInstance'

#############
# Main Code #
#############

MODULE = __import__('RDS_LOGGING_ENABLED')
RULE = MODULE.RDS_LOGGING_ENABLED()

CLIENT_FACTORY = MagicMock()

#example for mocking S3 API calls
RDS_CLIENT_MOCK = MagicMock()
CONFIG_CLIENT = MagicMock()


def mock_get_client(service, *args, **kwargs):
    if service == 'rds':
        return RDS_CLIENT_MOCK
    if service == 'config':
        return CONFIG_CLIENT
    raise Exception("Attempting to create an unknown client")


@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    db_instance_compliant = {"DBInstances": [
        {
            "DBInstanceIdentifier": "prod-dbms-backened",
            "Engine": "postgres",
            "EnabledCloudwatchLogsExports": [
                "postgresql",
                "upgrade"
            ]
        }]}

    db_instance_non_compliant = {"DBInstances": [
        {
            "DBInstanceIdentifier": "dbms-backened",
            "Engine": "postgres",
            "EnabledCloudwatchLogsExports": [
                "postgresql"
            ]
        }]}

    def setUp(self):
        pass

    def test_01_compliant(self):
        CONFIG_CLIENT.select_resource_config.return_value = {"Results": ['{"resourceName":"prod-dbms-backened"}']}
        RDS_CLIENT_MOCK.describe_db_instances.return_value = self.db_instance_compliant
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, "")
        print(response)
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, "prod-dbms-backened", RESOURCE_TYPE)
        ]
        print(resp_expected)
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_02_non_compliant(self):
        CONFIG_CLIENT.select_resource_config.return_value = {"Results": ['{"resourceName":"dbms-backened"}']}
        RDS_CLIENT_MOCK.describe_images.return_value = self.db_instance_non_compliant
        response = RULE.evaluate_periodic("", CLIENT_FACTORY, "")
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, "dbms-backened", RESOURCE_TYPE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
