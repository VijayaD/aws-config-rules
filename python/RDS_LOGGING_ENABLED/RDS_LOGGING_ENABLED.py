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

'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  RDS_LOGGING_ENABLED

Description:
  check whether respective logs are enabled or not.
      For Oracle engine -- ["trace", "audit", "alert", "listener"]
      For Postgres engine -- ["postgresql", "upgrade"]
      For MariaDB -- ["audit", "error", "general", "slowquery"]
      For Mysql -- ["audit", "error", "general", "slowquery"]
      For SqlServer -- ["error", "agent"]

Indicative Severity:
  Medium

Trigger:
  Periodic

Reports on:
  AWS::RDS::DBInstance

Rule Parameters:
  None

Scenarios:
  Scenario: 1
      Given: RDS DBinstance identifier is valid
      And: respective logfiles(e.g. Alert, Audit, Trace, Listener logs) are enabled by dbinstance engine(e.g. Oracle)
     Then: Return COMPLIANT

  Scenario: 2
      Given: RDS DBInstance identifier is valid
      And: one or more logs are not enabled
      Then: Return NON_COMPLIANT
'''

import json
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType


RESOURCE_TYPE = 'AWS::RDS::DBInstance'
PAGE_SIZE = 20

class RDS_LOGGING_ENABLED(ConfigRule):

    engine_logs = {
        'postgres': ["postgresql", "upgrade"],
        'mariadb': ["audit", "error", "general", "slowquery"],
        'mysql': ["audit", "error", "general", "slowquery"],

        'oracle-ee': ["trace", "audit", "alert", "listener"],
        'oracle-se': ["trace", "audit", "alert", "listener"],
        'oracle-se1': ["trace", "audit", "alert", "listener"],
        'oracle-se2': ["trace", "audit", "alert", "listener"],

        'sqlserver-ee': ["error", "agent"],
        'sqlserver-ex': ["error", "agent"],
        'sqlserver-se': ["error", "agent"],
        'sqlserver-web': ["error", "agent"],

    }

    # def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
    #     ###############################
    #     # Add your custom logic here. #
    #     ###############################
    #
    #     return [Evaluation(ComplianceType.NOT_APPLICABLE)]

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        evaluations = []
        rds_client = client_factory.build_client('rds')
        config_client = client_factory.build_client('config')
        for db_instance_identifier in self.describe_db_instances(config_client):
            response = rds_client.describe_db_instances(
                DBInstanceIdentifier=db_instance_identifier)
            engine = response['DBInstances'][0]['Engine']
            if 'EnabledCloudwatchLogsExports' in response['DBInstances'][0]:
                compliance_type, annotation = self.check_and_process(response, self.engine_logs[engine])
                evaluations.append(Evaluation(compliance_type, db_instance_identifier, RESOURCE_TYPE,
                                              annotation=annotation))
            else:
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT, db_instance_identifier, RESOURCE_TYPE,
                                              annotation="No Logs are enabled for this DBInstance"))
        return evaluations


    def describe_db_instances(self, config_client):
        sql_query = "SELECT resourceName WHERE resourceType = 'AWS::RDS::DBInstance';"
        next_token = True
        response = config_client.select_resource_config(Expression=sql_query, Limit=100)
        while next_token:
            for result in response['Results']:
                yield json.loads(result)['resourceName']
            if 'NextToken' in response:
                next_token = response['NextToken']
                response = config_client.select_resource_config(Expression=sql_query, NextToken=next_token,
                                                                Limit=PAGE_SIZE)
            else:
                next_token = False

    def check_and_process(self, response, logs_list):
        annotation = ''
        logs_enabled = response['DBInstances'][0]['EnabledCloudwatchLogsExports']
        print("logs enabled are: {}". format(logs_enabled))
        logs_not_enabled_list = list(set(logs_list) - set(logs_enabled))
        print("logs not enabled are: {}". format(logs_not_enabled_list))
        if len(logs_not_enabled_list) == 0:
            compliance_type = ComplianceType.COMPLIANT
        else:
            compliance_type = ComplianceType.NON_COMPLIANT
            annotation = '{} logs are not enabled'.format(logs_not_enabled_list)
        return compliance_type, annotation


################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = RDS_LOGGING_ENABLED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
