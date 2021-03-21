"""
Purpose

Example of how to provision an EKS cluster, create the IAM Roles for Service Accounts (IRSA) mappings,
and then deploy various required cluster add-ons (AWS LB Controller, ExternalDNS, Prometheus/Grafana,
AWS Elasticsearch, etc.)
"""

from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    aws_elasticsearch as es,
    aws_logs as logs,
    aws_certificatemanager as cm,  
    core
)
import os

# Set this to True in order to deploy a Bastion host to access your new cluster/environment
# The preferred option is to use a Client VPN instead so this defaults to False
deploy_bastion = True

# Deploy Client VPN?
deploy_client_vpn = True

# If VPN = True then create and upload your client and server certs as per putting the ARNs below
# https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html#mutual
client_certificate_arn="arn:aws:acm:ap-southeast-2:505070718513:certificate/6b85eefd-56b3-4461-8dda-19613170ba2d"
server_certificate_arn="arn:aws:acm:ap-southeast-2:505070718513:certificate/9b30b41a-89a1-416b-b2d2-bc76c26e9f15"

# CIDR Block for VPN Clients (has to be at least a /22)
vpn_client_cidr_block="10.1.0.0/22"

# Create a new VPC for the cluster?
# If you set this to False then specify the VPC name to use below
create_new_vpc = True

# Set this to the CIDR for your new VPC
vpc_cidr="10.0.0.0/22"

# Set this to the CIDR mask/size for your public subnets
vpc_cidr_mask_public=26

# Set this to the CIDR mask/size for your private subnets
vpc_cidr_mask_private=24

# If create_new_vpc is False then enter the name of the existing VPC to use
existing_vpc_name="VPC"

# Create a new role as the inital admin for the cluster?
create_new_cluster_admin_role = True

# If create_new_cluster_admin_role is False then provide the ARN of the existing role to use
existing_role_arn="arn:aws:iam::123456789123:role/RoleName"

class EKSClusterStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Either create a new IAM role to administrate the cluster or create a new one
        if (create_new_cluster_admin_role is True):
            cluster_admin_role = iam.Role(self, "ClusterAdminRole",
                assumed_by=iam.CompositePrincipal(
                    iam.AccountRootPrincipal(),
                    iam.ServicePrincipal("ec2.amazonaws.com")
                )
            )
            cluster_admin_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "eks:DescribeCluster"
                ],
                "Resource": "*"
            }
            cluster_admin_role.add_to_policy(iam.PolicyStatement.from_json(cluster_admin_policy_statement_json_1))
        else:
            cluster_admin_role = iam.Role.from_role_arn(self, "ClusterAdminRole",
                role_arn=existing_role_arn
            )
    
        # Either create a new VPC with the options below OR import an existing one by name
        if (create_new_vpc is True):
            eks_vpc = ec2.Vpc(
                self, "VPC",
                # We are choosing to spread our VPC across 3 availability zones
                max_azs=3,
                # We are creating a VPC that has a /22, 1024 IPs, for our EKS cluster.
                # I am using that instead of a /16 etc. as I know many companies have constraints here
                # If you can go bigger than this great - but I would try not to go much smaller if you can
                # I use https://www.davidc.net/sites/default/subnets/subnets.html to me work out the CIDRs
                cidr=vpc_cidr,
                subnet_configuration=[
                    # 3 x Public Subnets (1 per AZ) with 64 IPs each for our ALBs and NATs
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PUBLIC,
                        name="Public",
                        cidr_mask=vpc_cidr_mask_public
                    ), 
                    # 3 x Private Subnets (1 per AZ) with 256 IPs each for our Nodes and Pods
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PRIVATE,
                        name="Private",
                        cidr_mask=vpc_cidr_mask_private
                    )
                ]
            )   
        else:
            eks_vpc = ec2.Vpc.from_lookup(self, 'VPC', vpc_name=existing_vpc_name)

        # Create an EKS Cluster
        eks_cluster = eks.Cluster(
            self, "cluster",
            vpc=eks_vpc,
            masters_role=cluster_admin_role,
            # Use a Managed Node Group for our initial capacity
            default_capacity_type=eks.DefaultCapacityType.NODEGROUP,
            default_capacity_instance=ec2.InstanceType("m5.large"),
            default_capacity=3,
            # Make our cluster's control plane accessible only within our private VPC
            # This means that we'll have to ssh to a jumpbox/bastion or set up a VPN to manage it
            endpoint_access=eks.EndpointAccess.PRIVATE,
            version=eks.KubernetesVersion.V1_19
        )

        # Create the mapped AWS IAM Roles and Kubernetes Service Accounts for IRSA
        # For more info see https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html

        # AWS Load Balancer Controller
        alb_service_account = eks_cluster.add_service_account(
            "aws-load-balancer-controller",
            name="aws-load-balancer-controller",
            namespace="kube-system"
        )

        # Create the PolicyStatements to attach to the role
        # I couldn't find a way to get this to work with a whole PolicyDocument and there are 10 statements
        alb_policy_statement_json_1 = {
            "Effect": "Allow",
            "Action": [
                "acm:DescribeCertificate",
                "acm:ListCertificates",
                "acm:GetCertificate"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_2 = {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:CreateSecurityGroup",
                "ec2:CreateTags",
                "ec2:DeleteTags",
                "ec2:DeleteSecurityGroup",
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeTags",
                "ec2:DescribeVpcs",
                "ec2:ModifyInstanceAttribute",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_3 = {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:AddListenerCertificates",
                "elasticloadbalancing:AddTags",
                "elasticloadbalancing:CreateListener",
                "elasticloadbalancing:CreateLoadBalancer",
                "elasticloadbalancing:CreateRule",
                "elasticloadbalancing:CreateTargetGroup",
                "elasticloadbalancing:DeleteListener",
                "elasticloadbalancing:DeleteLoadBalancer",
                "elasticloadbalancing:DeleteRule",
                "elasticloadbalancing:DeleteTargetGroup",
                "elasticloadbalancing:DeregisterTargets",
                "elasticloadbalancing:DescribeListenerCertificates",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeRules",
                "elasticloadbalancing:DescribeSSLPolicies",
                "elasticloadbalancing:DescribeTags",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetGroupAttributes",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:ModifyListener",
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "elasticloadbalancing:ModifyRule",
                "elasticloadbalancing:ModifyTargetGroup",
                "elasticloadbalancing:ModifyTargetGroupAttributes",
                "elasticloadbalancing:RegisterTargets",
                "elasticloadbalancing:RemoveListenerCertificates",
                "elasticloadbalancing:RemoveTags",
                "elasticloadbalancing:SetIpAddressType",
                "elasticloadbalancing:SetSecurityGroups",
                "elasticloadbalancing:SetSubnets",
                "elasticloadbalancing:SetWebAcl"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_4 = {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole",
                "iam:GetServerCertificate",
                "iam:ListServerCertificates"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_5 = {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPoolClient"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_6 = {
            "Effect": "Allow",
            "Action": [
                "waf-regional:GetWebACLForResource",
                "waf-regional:GetWebACL",
                "waf-regional:AssociateWebACL",
                "waf-regional:DisassociateWebACL"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_7 = {
            "Effect": "Allow",
            "Action": [
                "tag:GetResources",
                "tag:TagResources"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_8 = {
            "Effect": "Allow",
            "Action": [
                "waf:GetWebACL"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_9 = {
            "Effect": "Allow",
            "Action": [
                "wafv2:GetWebACL",
                "wafv2:GetWebACLForResource",
                "wafv2:AssociateWebACL",
                "wafv2:DisassociateWebACL"
            ],
            "Resource": "*"
        }
        alb_policy_statement_json_10 = {
            "Effect": "Allow",
            "Action": [
                "shield:DescribeProtection",
                "shield:GetSubscriptionState",
                "shield:DeleteProtection",
                "shield:CreateProtection",
                "shield:DescribeSubscription",
                "shield:ListProtections"
            ],
            "Resource": "*"
        }
        
        # Attach the necessary permissions
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_1))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_2))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_3))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_4))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_5))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_6))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_7))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_8))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_9))
        alb_service_account.add_to_policy(iam.PolicyStatement.from_json(alb_policy_statement_json_10))

        # External DNS Controller
        externaldns_service_account = eks_cluster.add_service_account(
            "external-dns",
            name="external-dns",
            namespace="kube-system"
        )

        # Create the PolicyStatements to attach to the role
        externaldns_policy_statement_json_1 = {
        "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/*"
            ]
        }
        externaldns_policy_statement_json_2 = {
            "Effect": "Allow",
            "Action": [
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets"
            ],
            "Resource": [
                "*"
            ]
        }

        # Attach the necessary permissions
        externaldns_service_account.add_to_policy(iam.PolicyStatement.from_json(externaldns_policy_statement_json_1))
        externaldns_service_account.add_to_policy(iam.PolicyStatement.from_json(externaldns_policy_statement_json_2))

        # AWS EBS CSI Driver
        awsebscsidriver_service_account = eks_cluster.add_service_account(
            "awsebscsidriver",
            name="awsebscsidriver",
            namespace="kube-system"
        )

        # Create the PolicyStatements to attach to the role
        awsebscsidriver_policy_statement_json_1 = {
            "Effect": "Allow",
            "Action": [
                "ec2:AttachVolume",
                "ec2:CreateSnapshot",
                "ec2:CreateTags",
                "ec2:CreateVolume",
                "ec2:DeleteSnapshot",
                "ec2:DeleteTags",
                "ec2:DeleteVolume",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeInstances",
                "ec2:DescribeSnapshots",
                "ec2:DescribeTags",
                "ec2:DescribeVolumes",
                "ec2:DescribeVolumesModifications",
                "ec2:DetachVolume",
                "ec2:ModifyVolume"
            ],
            "Resource": "*"
        }

        # Attach the necessary permissions
        awsebscsidriver_service_account.add_to_policy(iam.PolicyStatement.from_json(awsebscsidriver_policy_statement_json_1))

        # AWS EFS CSI Driver
        awsefscsidriver_service_account = eks_cluster.add_service_account(
            "awsefscsidriver",
            name="awsefscsidriver",
            namespace="kube-system"
        )

        # Create the PolicyStatements to attach to the role
        awsefscsidriver_policy_statement_json_1 = {
            "Effect": "Allow",
            "Action": [
                "elasticfilesystem:DescribeAccessPoints",
                "elasticfilesystem:DescribeFileSystems"
            ],
            "Resource": "*"
        }
        awsefscsidriver_policy_statement_json_2 = {
            "Effect": "Allow",
            "Action": [
                "elasticfilesystem:CreateAccessPoint"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {
                "aws:RequestTag/efs.csi.aws.com/cluster": "true"
                }
            }
        }
        awsefscsidriver_policy_statement_json_3 = {
            "Effect": "Allow",
            "Action": "elasticfilesystem:DeleteAccessPoint",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
                }
            }
        }

        # Attach the necessary permissions
        awsefscsidriver_service_account.add_to_policy(iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_1))
        awsefscsidriver_service_account.add_to_policy(iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_2))
        awsefscsidriver_service_account.add_to_policy(iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_3))

        # cluster-autoscaler
        clusterautoscaler_service_account = eks_cluster.add_service_account(
            "clusterautoscaler",
            name="clusterautoscaler",
            namespace="kube-system"
        )

        # Create the PolicyStatements to attach to the role
        clusterautoscaler_policy_statement_json_1 = {
            "Effect": "Allow",
            "Action": [
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeTags",
                "autoscaling:SetDesiredCapacity",
                "autoscaling:TerminateInstanceInAutoScalingGroup"
            ],
            "Resource": "*"
        }

        # Attach the necessary permissions
        clusterautoscaler_service_account.add_to_policy(iam.PolicyStatement.from_json(clusterautoscaler_policy_statement_json_1))        

        # Install our cluster add-ons
        
        # Deploy the AWS Load Balancer Controller from the AWS Helm Chart
        # For more info check out https://github.com/aws/eks-charts/tree/master/stable/aws-load-balancer-controller
        awslbcontroller_chart = eks_cluster.add_helm_chart(
            "aws-load-balancer-controller",
            chart="aws-load-balancer-controller",
            version="1.1.5",
            release="awslbcontroller-1-1-5",
            repository="https://aws.github.io/eks-charts",
            namespace="kube-system",
            values={
                "clusterName": eks_cluster.cluster_name,
                "region": self.region,
                "vpcId": eks_vpc.vpc_id,
                "serviceAccount": {
                    "create": False,
                    "name": "aws-load-balancer-controller"
                },
                "replicaCount": 2
            }
        )

        # Deploy External DNS from the bitnami Helm chart
        # For more info see https://github.com/bitnami/charts/tree/master/bitnami/external-dns
        externaldns_chart = eks_cluster.add_helm_chart(
            "external-dns",
            chart="external-dns",
            version="4.9.0",
            release="externaldns-4-9-0",
            repository="https://charts.bitnami.com/bitnami",
            namespace="kube-system",
            values={
                "provider": "aws",
                "aws": {
                    "region": self.region
                },
                "serviceAccount": {
                    "create": False,
                    "name": "external-dns"
                },
                "podSecurityContext": {
                    "fsGroup": 65534
                },
                "replicas": 2
            }
        )    
        
        # Deploy a managed Amazon Elasticsearch and a fluent-bit to ship our container logs there

        # Create a new ElasticSearch Domain
        # NOTE: I changed this to a removal_policy of DESTROY to help cleanup while I was 
        # developing/iterating on the project. If you comment out that line it defaults to keeping 
        # the Domain upon deletion of the CloudFormation stack so you won't lose your log data
        es_capacity = es.CapacityConfig(
            data_nodes=1,
            data_node_instance_type="r5.large.elasticsearch",
            master_nodes=0,
            master_node_instance_type="r5.large.elasticsearch"
        )
        es_ebs = es.EbsOptions(
            enabled=True,
            volume_type=ec2.EbsDeviceVolumeType.GP2,
            volume_size=10
        )
        es_domain = es.Domain(
            self, "ESDomain",
            removal_policy=core.RemovalPolicy.DESTROY,
            version=es.ElasticsearchVersion.V7_9,
            vpc_options=es.VpcOptions(
                subnets=[eks_vpc.private_subnets[0]],
                security_groups=[eks_cluster.cluster_security_group]
            ),
            capacity=es_capacity,
            ebs=es_ebs
        )
        
        # Create the Service Account
        fluentbit_service_account = eks_cluster.add_service_account(
            "fluentbit",
            name="fluentbit",
            namespace="kube-system"
        )

        fluentbit_policy_statement_json_1 = {
        "Effect": "Allow",
            "Action": [
                "es:ESHttp*"
            ],
            "Resource": [
                es_domain.domain_arn
            ]
        }

        # Add the policies to the service account
        fluentbit_service_account.add_to_policy(iam.PolicyStatement.from_json(fluentbit_policy_statement_json_1))
        es_domain.grant_write(fluentbit_service_account)

        # For more info check out https://github.com/aws/eks-charts/tree/master/stable/aws-for-fluent-bit
        fluentbit_chart = eks_cluster.add_helm_chart(
            "fluentbit",
            chart="aws-for-fluent-bit",
            version="0.1.6",
            release="fluentbit-0-1-6",
            repository="https://aws.github.io/eks-charts",
            namespace="kube-system",
            values={
                "serviceAccount": {
                    "create": False,
                    "name": "fluentbit"
                },
                "cloudWatch": {
                    "enabled": False
                },
                "firehose": {
                    "enabled": False
                },
                "kinesis": {
                    "enabled": False
                },
                "elasticsearch": {
                    "awsRegion": self.region,
                    "host": es_domain.domain_endpoint
                }
            }
        )

        # Deploy Prometheus and Grafana
        # TODO Replace this with the new AWS Managed Prometheus and Grafana when it is Generally Available (GA)
        # For more information see https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack
        prometheus_chart = eks_cluster.add_helm_chart(
            "metrics",
            chart="kube-prometheus-stack",
            version="14.0.1",
            release="prometheus-14-0-1",
            repository="https://prometheus-community.github.io/helm-charts",
            namespace="kube-system",
            values={
                "prometheus": {
                    "prometheusSpec": {
                    "storageSpec": {
                        "volumeClaimTemplate": {
                        "spec": {
                            "accessModes": [
                            "ReadWriteOnce"
                            ],
                            "resources": {
                            "requests": {
                                "storage": "8Gi"
                            }
                            },
                            "storageClassName": "gp2"
                        }
                        }
                    }
                    }
                },
                "alertmanager": {
                    "alertmanagerSpec": {
                    "storage": {
                        "volumeClaimTemplate": {
                        "spec": {
                            "accessModes": [
                            "ReadWriteOnce"
                            ],
                            "resources": {
                            "requests": {
                                "storage": "2Gi"
                            }
                            },
                            "storageClassName": "gp2"
                        }
                        }
                    }
                    }
                },
                "grafana": {
                    "persistence": {
                        "enabled": "true",
                        "storageClassName": "gp2"
                    }
                }
            }          
        )

        # Deploy an internal NLB to Grafana
        grafananlb_manifest = eks_cluster.add_manifest("GrafanaNLB",{
            "kind": "Service",
            "apiVersion": "v1",
            "metadata": {
                "name": "grafana-nlb",
                "namespace": "kube-system",
                "annotations": {
                    "service.beta.kubernetes.io/aws-load-balancer-type": "nlb-ip",
                    "service.beta.kubernetes.io/aws-load-balancer-internal": "true"
                }
            },
            "spec": {
                "ports": [
                {
                    "name": "service",
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 3000
                }
                ],
                "selector": {
                    "app.kubernetes.io/name": "grafana"
                },
                "type": "LoadBalancer"
            }
        })

        # Install the AWS EBS CSI Driver
        # For more info see https://github.com/kubernetes-sigs/aws-ebs-csi-driver
        awsebscsi_chart = eks_cluster.add_helm_chart(
            "aws-ebs-csi-driver",
            chart="aws-ebs-csi-driver",
            version="0.9.14",
            release="awsebscsidriver-0-9-14",
            repository="https://kubernetes-sigs.github.io/aws-ebs-csi-driver",
            namespace="kube-system",
            values={
                "region": self.region,
                "enableVolumeScheduling": True,
                "enableVolumeResizing": True,
                "enableVolumeSnapshot": True,
                "serviceAccount": {
                    "controller": {
                        "create": False,
                        "name": "awsebscsidriver"
                    },
                    "snapshot": {
                        "create": False,
                        "name": "awsebscsidriver"
                    }
                }
            }
        )

        # Install the AWS EFS CSI Driver
        # For more info see https://github.com/kubernetes-sigs/aws-efs-csi-driver
        awsefscsi_chart = eks_cluster.add_helm_chart(
            "aws-efs-csi-driver",
            chart="aws-efs-csi-driver",
            version="1.1.1",
            release="awsefscsidriver-1-1-1",
            repository="https://kubernetes-sigs.github.io/aws-efs-csi-driver/",
            namespace="kube-system",
            values={
                "serviceAccount": {
                    "controller": {
                        "create": False,
                        "name": "awsefscsidriver"
                    }
                }
            }
        )

        # Install the Cluster Autoscaler
        # For more info see https://github.com/kubernetes/autoscaler
        clusterautoscaler_chart = eks_cluster.add_helm_chart(
            "cluster-autoscaler",
            chart="cluster-autoscaler",
            version="9.7.0",
            release="clusterautoscaler-9-7-0",
            repository="https://kubernetes.github.io/autoscaler",
            namespace="kube-system",
            values={
                "autoDiscovery": {
                    "clusterName": eks_cluster.cluster_name
                },
                "awsRegion": self.region,
                "rbac": {
                    "serviceAccount": {
                        "create": False,
                        "name": "clusterautoscaler"
                    }
                },
                "replicaCount": 2
            }
        )

        # Install the metrics-server (required for the HPA)
        # For more info see https://github.com/bitnami/charts/tree/master/bitnami/metrics-server
        metricsserver_chart = eks_cluster.add_helm_chart(
            "metrics-server",
            chart="metrics-server",
            version="5.8.0",
            release="metricsserver-5-8-0",
            repository="https://charts.bitnami.com/bitnami",
            namespace="kube-system",
            values={
                "replicas": 2
            }
        )

        # Install the OPA Gatekeeper
        # For more info see https://github.com/open-policy-agent/gatekeeper
        gatekeeper_chart = eks_cluster.add_helm_chart(
            "gatekeeper",
            chart="gatekeeper",
            version="3.4.0-beta.0",
            release="gatekeeper-3-4-0-beta",
            repository="https://open-policy-agent.github.io/gatekeeper/charts",
            namespace="kube-system"
        )

        # The service accounts must exist before the charts can use them
        awslbcontroller_chart.node.add_dependency(alb_service_account)
        externaldns_chart.node.add_dependency(externaldns_service_account)
        fluentbit_chart.node.add_dependency(fluentbit_service_account)
        awsebscsi_chart.node.add_dependency(awsebscsidriver_service_account)
        awsefscsi_chart.node.add_dependency(awsefscsidriver_service_account)
        clusterautoscaler_chart.node.add_dependency(clusterautoscaler_service_account)

        # Gatekeeper being an admission controller needs to be deployed last to not interfere
        gatekeeper_chart.node.add_dependency(metricsserver_chart)
        gatekeeper_chart.node.add_dependency(clusterautoscaler_chart)
        gatekeeper_chart.node.add_dependency(awsebscsi_chart)
        gatekeeper_chart.node.add_dependency(awsefscsi_chart)
        gatekeeper_chart.node.add_dependency(grafananlb_manifest)
        gatekeeper_chart.node.add_dependency(prometheus_chart)
        gatekeeper_chart.node.add_dependency(fluentbit_chart)
        gatekeeper_chart.node.add_dependency(externaldns_chart)
        gatekeeper_chart.node.add_dependency(awslbcontroller_chart)


        # Output the Kibana address in our CloudFormation Stack
        core.CfnOutput(
            self, "KibanaAddress",
            value=es_domain.domain_endpoint + "/_plugin/kibana/",
            description="Private endpoint for this EKS environment's Kibana to consume the logs",

        )

        # If you have a 'True' in the deploy_bastion variable at the top of the file we'll deploy
        # a basion server that you can connect to VS Code via HTTP on port 8080 on the public IP
        # The password is the instance ID of the CodeServerInstance (find in the console)
        if (deploy_bastion is True):
            # Create an Instance Profile for our Admin Role to assume w/EC2
            cluster_admin_role_instance_profile = iam.CfnInstanceProfile(
                self, "ClusterAdminRoleInstanceProfile",
                roles=[cluster_admin_role.role_name]        
            )
            
            # Create code-server bastion
            # Get Latest Amazon Linux AMI
            amzn_linux = ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                edition=ec2.AmazonLinuxEdition.STANDARD,
                virtualization=ec2.AmazonLinuxVirt.HVM,
                storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE
                )

            # Create SecurityGroup for code-server
            bastion_security_group = ec2.SecurityGroup(
                self, "BastionSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )
            bastion_security_group.add_ingress_rule(
                ec2.Peer.any_ipv4(),
                ec2.Port.tcp(8080)
            )

            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                bastion_security_group,
                ec2.Port.all_traffic()
            )

            # Create our EC2 instance running CodeServer
            code_server_instance = ec2.Instance(
                self, "CodeServerInstance",
                instance_type=ec2.InstanceType("t3.large"),
                machine_image=amzn_linux,
                role=cluster_admin_role,
                vpc=eks_vpc,
                vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
                security_group=bastion_security_group,
                block_devices=[ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(20))]
            )

            # Add UserData
            code_server_instance.user_data.add_commands("mkdir -p ~/.local/lib ~/.local/bin ~/.config/code-server")
            code_server_instance.user_data.add_commands("curl -fL https://github.com/cdr/code-server/releases/download/v3.9.1/code-server-3.9.1-linux-amd64.tar.gz | tar -C ~/.local/lib -xz")
            code_server_instance.user_data.add_commands("mv ~/.local/lib/code-server-3.9.1-linux-amd64 ~/.local/lib/code-server-3.9.1")
            code_server_instance.user_data.add_commands("ln -s ~/.local/lib/code-server-3.9.1/bin/code-server ~/.local/bin/code-server")
            code_server_instance.user_data.add_commands("echo \"bind-addr: 0.0.0.0:8080\" > ~/.config/code-server/config.yaml")
            code_server_instance.user_data.add_commands("echo \"auth: password\" >> ~/.config/code-server/config.yaml")
            code_server_instance.user_data.add_commands("echo \"password: $(curl -s http://169.254.169.254/latest/meta-data/instance-id)\" >> ~/.config/code-server/config.yaml")
            code_server_instance.user_data.add_commands("echo \"cert: false\" >> ~/.config/code-server/config.yaml")
            code_server_instance.user_data.add_commands("~/.local/bin/code-server &")
            code_server_instance.user_data.add_commands("curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/kubectl")
            code_server_instance.user_data.add_commands("chmod +x ./kubectl")
            code_server_instance.user_data.add_commands("mv ./kubectl /usr/local/bin")
            
            # Output the Bastion adddress
            core.CfnOutput(
                self, "BastionAddress",
                value="http://"+code_server_instance.instance_public_ip+":8080",
                description="Address to reach your Bastion's VS Code Web UI",
            )
        
        if (deploy_client_vpn is True):
            # Create and upload your client and server certs as per https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html#mutual
            # And then put the ARNs for them into the items below
            client_cert = cm.Certificate.from_certificate_arn(
                self, "ClientCert",
                certificate_arn=client_certificate_arn)
            server_cert = cm.Certificate.from_certificate_arn(
                self, "ServerCert",
                certificate_arn=server_certificate_arn)

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
                client_cidr_block=vpn_client_cidr_block,
                server_certificate_arn=server_cert.certificate_arn,
                connection_log_options={
                    "enabled": True,
                    "cloudwatchLogGroup": log_group.log_group_name,
                    "cloudwatchLogStream": log_stream.log_stream_name
                },
                split_tunnel=True,
                security_group_ids=[eks_cluster.cluster_security_group_id]
            )

            ec2.CfnClientVpnAuthorizationRule(
                self, "ClientVpnAuthRule",
                client_vpn_endpoint_id=endpoint.ref,
                target_network_cidr=eks_vpc.vpc_cidr_block,
                authorize_all_groups=True,
                description="Authorize the Client VPN access to our VPC CIDR"
            )

            ec2.CfnClientVpnTargetNetworkAssociation(
                self, "ClientVpnNetworkAssociation",
                client_vpn_endpoint_id=endpoint.ref,
                subnet_id=eks_vpc.private_subnets[0].subnet_id
            )

app = core.App()
# Note that if we didn't pass through the ACCOUNT and REGION from these environment variables that
# it won't let us create 3 AZs and will only create a max of 2 - even when we ask for 3 in eks_vpc
eks_cluster_stack = EKSClusterStack(app, "EKSClusterStack", env=core.Environment(
    account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),
    region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])))
app.synth()