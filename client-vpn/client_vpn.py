"""
Purpose

This will deploy an AWS Client VPN to access the priavte EKS cluster, Kibana and Grafana
"""

from aws_cdk import (
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_certificatemanager as cm,    
    core
)
import os

class ClientVPNStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create and upload your client and server certs as per https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html#mutual
        # And then put the ARNs for them into the items below
        client_cert = cm.Certificate.from_certificate_arn(
            self, "ClientCert",
            certificate_arn="arn:aws:acm:ap-southeast-2:505070718513:certificate/6b85eefd-56b3-4461-8dda-19613170ba2d")
        server_cert = cm.Certificate.from_certificate_arn(
            self, "ServerCert",
            certificate_arn="arn:aws:acm:ap-southeast-2:505070718513:certificate/9b30b41a-89a1-416b-b2d2-bc76c26e9f15")

        # Create CloudWatch Log Group and Stream and keep the logs for 1 month
        log_group = logs.LogGroup(
            self, "VPNLogGroup",
            retention=logs.RetentionDays.ONE_MONTH
        )
        log_stream = log_group.add_stream("VPNLogStream")

        endpoint = ec2.CfnClientVpnEndpoint(
            self, "VPNEndpoint",
            description="EKS Client VPN",
            authentication_options=[{
                "type": "certificate-authentication",
                "mutualAuthentication": {
                    "clientRootCertificateChainArn": client_cert.certificate_arn
                }
            }],
            client_cidr_block="10.2.0.0/22",
            server_certificate_arn=server_cert.certificate_arn,
            connection_log_options={
                "enabled": True,
                "cloudwatchLogGroup": log_group.log_group_name,
                "cloudwatchLogStream": log_stream.log_stream_name
            },
            split_tunnel=True
        )

        ec2.CfnClientVpnAuthorizationRule(
            self, "ClientVpnAuthRule",
            client_vpn_endpoint_id=endpoint.ref,
            target_network_cidr="10.0.0.0/22",
            authorize_all_groups=True,
            description="Authorize the Client VPN access to our VPC CIDR"
        )

app = core.App()
# Note that if we didn't pass through the ACCOUNT and REGION from these environment variables that
# it won't let us create 3 AZs and will only create a max of 2 - even when we ask for 3 in eks_vpc
client_vpn_stack = ClientVPNStack(app, "ClientVPNStack")
app.synth()