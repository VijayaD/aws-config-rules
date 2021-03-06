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
"""
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  IAM_ROLE_NOT_USED

Description:
  Check that an AWS IAM Role is being used in the last X days, default value is 90 days

Rationale:
  Ensure that no AWS IAM Role is unused and make an action if unused (e.g. delete the user).

Indicative Severity:
  Low

Trigger:
  Periodic

Reports on:
  AWS::IAM::Role

Rule Parameters:
  DaysBeforeUnused
   (Optional) Number of days when AWS IAM Roles are considered unused (default 90 days).
   If the value is 0, IAM Roles must be used at least once every 24 hours.

Scenarios:
  Scenario: 1
    Given: Rule parameter Days is not a positive integer
     Then: Return Error
  Scenario: 2
    Given: No AMI Role is unused from last DaysBeforeUnused days
     Then: Return COMPLIANT
  Scenario: 3
    Given: One or more AMI Role is unused from last DaysBeforeUnused days
     Then: Return NON_COMPLIANT
"""
import json
from datetime import datetime, timezone
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, InvalidParametersError

CURRENT_TIME = datetime.now(timezone.utc)
RESOURCE_TYPE = 'AWS::IAM::Role'
PAGE_SIZE = 100
DEFAULT_DAYS = 90

class IAM_ROLE_NOT_USED(ConfigRule):

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        evaluations = []
        iam_client = client_factory.build_client(service='iam')
        config_client = client_factory.build_client(service='config')
        for role_name in describe_roles(config_client):
            role_data = iam_client.get_role(RoleName=role_name)
            role = role_data.get('Role')
            last_used = role.get('RoleLastUsed')
            if last_used:
                diff = (CURRENT_TIME - last_used.get('LastUsedDate')).days
            else:
                created_on = role.get('CreateDate')
                diff = (CURRENT_TIME - created_on).days
            days_before_unused = valid_rule_parameters.get('DaysBeforeUnused')
            if diff <= days_before_unused:
                evaluations.append(Evaluation(ComplianceType.COMPLIANT, role_name, RESOURCE_TYPE))
            else:
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT, role_name, RESOURCE_TYPE,
                                              annotation="This AWS IAM Role has not been used within the last {} day(s)".format(days_before_unused)))
        return evaluations

    def evaluate_parameters(self, rule_parameters):

        if not rule_parameters.get('DaysBeforeUnused'):
            rule_parameters['DaysBeforeUnused'] = DEFAULT_DAYS

        # The int() function will raise an error if the string configured can't be converted to an integer
        try:
            rule_parameters['DaysBeforeUnused'] = int(rule_parameters['DaysBeforeUnused'])
        except ValueError:
            raise InvalidParametersError('The parameter "DaysBeforeUnused" must be a integer')

        if rule_parameters['DaysBeforeUnused'] < 0:
            raise InvalidParametersError('The parameter "DaysBeforeUnused" must be greater than or equal to 0')
        return rule_parameters

def describe_roles(config_client):
    sql = "select * where resourceType = 'AWS::IAM::Role'"
    next_token = True
    response = config_client.select_resource_config(Expression=sql, Limit=PAGE_SIZE)
    while next_token:
        for result in response['Results']:
            yield json.loads(result)['resourceName']
        if 'NextToken' in response:
            next_token = response['NextToken']
            response = config_client.select_resource_config(Expression=sql, NextToken=next_token, Limit=PAGE_SIZE)
        else:
            next_token = False

def lambda_handler(event, context):
    my_rule = IAM_ROLE_NOT_USED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
