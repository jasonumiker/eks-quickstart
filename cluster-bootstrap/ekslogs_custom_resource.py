"""
Purpose

Enable all the control plane logs for EKS via Lambda since it doesn't yet have CloudFormation support
"""

from aws_cdk import (
    aws_iam as iam,
    custom_resources as custom_resources,
    core,
)
import os

class EKSLogsObjectResource(core.Construct):
    """EKS SDK updateClusterConfig
    Arguments:
        :param eks_name -- The name of the EKS cluster to enable logging on
        :param eks_arn -- The ARN of the EKS cluster to enable logging on
    """

    def __init__(self, scope: core.Construct, id: str, eks_name: str, eks_arn: str, log_retention=None) -> None:
        super().__init__(scope, id)
        
        on_create = self.get_on_create_update(eks_name=eks_name)

        lambda_role = iam.Role(self, "LambdaRole",
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")],
            )

        lambda_policy = custom_resources.AwsCustomResourcePolicy.from_statements([
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["eks:UpdateClusterConfig"],
                resources=["*"]
            )
        ])

        custom_resources.AwsCustomResource(scope=scope,
            id=f'{id}-AWSCustomResource',
            log_retention=log_retention,
            on_create=on_create,
            resource_type='Custom::AWS-EKS-Logs-Object',
            role=lambda_role,
            policy=lambda_policy
        )

    def get_on_create_update(self, eks_name):
        create_params = {
            "name": eks_name,
            "logging": {
                "clusterLogging": [
                    {
                        "enabled": True,
                        "types": ["api", "audit", "authenticator", "controllerManager", "scheduler"]
                    }]
            }
        }

        # api_version=None uses the latest api
        on_create = custom_resources.AwsSdkCall(
            action='updateClusterConfig',
            service='EKS',
            parameters=create_params,
            physical_resource_id=custom_resources.PhysicalResourceId.of(f'{eks_name}Log-CR')
        )
        return on_create