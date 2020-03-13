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
  RDS_LOGGING_ENABLED

Description:
  Check that respective logs of Amazon RDS are enabled.
  The result is NON_COMPLIANT if any log types are not enabled.
      Oracle:       (Alert, Audit, Trace, Listener)
      PostgreSQL:   (Postgresql, Upgrade)
      MySQL:        (Audit, Error, General, SlowQuery)
      MariaDB:      (Audit, Error, General, SlowQuery)
      SQL Server:   (Error, Agent)
      Aurora:       (Audit, Error, General, SlowQuery)
      Aurora-MySQL: (Audit, Error, General, SlowQuery)
      Aurora-PostgreSQL: (Postgresql, Upgrade)

Indicative Severity:
  Medium

Trigger:
  Configuration change on AWS::RDS::DBInstance

Reports on:
  AWS::RDS::DBInstance

Rule Parameters:
  None

Scenarios:
  Scenario: 1
    Given: 'enabledCloudwatchLogsExports' in configuration item of Amazon RDS instance has all log types enabled
    Then: Return COMPLIANT

  Scenario: 2
    Given: 'enabledCloudwatchLogsExports' in configuration item of Amazon RDS instance has one or more log types not enabled
    Then: Return NON_COMPLIANT
"""

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType


class RDS_LOGGING_ENABLED(ConfigRule):

    engine_logs = {
        'postgres':      ["postgresql", "upgrade"],
        'mariadb':       ["audit", "error", "general", "slowquery"],
        'mysql':         ["audit", "error", "general", "slowquery"],
        'oracle-ee':     ["trace", "audit", "alert", "listener"],
        'oracle-se':     ["trace", "audit", "alert", "listener"],
        'oracle-se1':    ["trace", "audit", "alert", "listener"],
        'oracle-se2':    ["trace", "audit", "alert", "listener"],
        'sqlserver-ee':  ["error", "agent"],
        'sqlserver-ex':  ["error", "agent"],
        'sqlserver-se':  ["error", "agent"],
        'sqlserver-web': ["error", "agent"],
        'aurora':        ["audit", "error", "general", "slowquery"],
        'aurora-mysql':  ["audit", "error", "general", "slowquery"],
        'aurora-postgresql': ["postgresql", "upgrade"]
    }

    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        configuration = configuration_item.get('configuration')
        engine = configuration.get('engine')
        if engine:
            logs_list = self.engine_logs.get(engine)
            logs_enabled_list = configuration.get('enabledCloudwatchLogsExports', [])
            logs_not_enabled_list = list(set(logs_list) - set(logs_enabled_list))
            if logs_not_enabled_list:
                return [Evaluation(ComplianceType.NON_COMPLIANT,
                                   annotation='{} logs are not enabled'.format(sorted(logs_not_enabled_list)))]
            return [Evaluation(ComplianceType.COMPLIANT)]
        return [Evaluation(ComplianceType.NOT_APPLICABLE, annotation="Engine is not defined")]


def lambda_handler(event, context):
    my_rule = RDS_LOGGING_ENABLED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
