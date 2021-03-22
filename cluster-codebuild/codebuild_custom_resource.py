"""
Purpose

Run our CodeBuild Project once when the Stack is first provisioned
"""

from aws_cdk import (
    aws_iam as iam,
    custom_resources as custom_resources,
    core,
)
import os

class CodeBuildObjectResource(core.Construct):
    """S3 Object constructs that uses AWSCustomResource internally
    Arguments:
        :param codebuild_name -- The CodeBuild Project we want to run
        :param log_retention: The number of days log events of the Lambda function implementing this custom resource are kept in CloudWatch Logs. 
                              Default: logs.RetentionDays.INFINITE
    """

    def __init__(self, scope: core.Construct, id: str, codebuild_name: str, codebuild_arn: str, log_retention=None) -> None:
        super().__init__(scope, id)
        
        on_create = self.get_on_create_update(codebuild_name=codebuild_name)

        lambda_role = iam.Role(self, "LambdaRole",
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")],
            )

        lambda_policy = custom_resources.AwsCustomResourcePolicy.from_statements([
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["codebuild:StartBuild"],
                resources=[codebuild_arn]
            )
        ])

        custom_resources.AwsCustomResource(scope=scope,
            id=f'{id}-AWSCustomResource',
            log_retention=log_retention,
            on_create=on_create,
            resource_type='Custom::AWS-CodeBuild-Object',
            role=lambda_role,
            policy=lambda_policy
        )

    def get_on_create_update(self, codebuild_name):
        create_params = {
            "projectName": codebuild_name,
        }

        # api_version=None uses the latest api
        on_create = custom_resources.AwsSdkCall(
            action='startBuild',
            service='CodeBuild',
            parameters=create_params,
            physical_resource_id=custom_resources.PhysicalResourceId.of(f'{codebuild_name}-CR')
        )
        return on_create