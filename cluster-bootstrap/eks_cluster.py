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
    core
)
import os

class EKSClusterStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Either creat a new IAM role to administrate the cluster or create a new one
        # If you'd prefer to use an existing role for this comment out the first block 
        # and then uncomment the one underneath filling in the role's ARN
        cluster_admin_role = iam.Role(self, "ClusterAdminRole",
            assumed_by=iam.CompositePrincipal(iam.AccountRootPrincipal())
        )   
        #cluster_admin_role = iam.Role.from_role_arn(self, "ClusterAdminRole",
        #    role_arn="arn:aws:iam::505070718513:role/IsenAdminRole"
        #)
    
        # Either create a new VPC with the options below OR import an existing one by name:
        # To import an existing one comment out the first eks_vpc block out then un-comment 
        # the following one and change the vpc_name to match the name of the VPC you'd like to use
        eks_vpc = ec2.Vpc(
            self, "VPC",
            # We are choosing to spread our VPC across 3 availability zones
            max_azs=3,
            # We are creating a VPC that has a /22, 1024 IPs, for our EKS cluster.
            # I am using that instead of a /16 etc. as I know many companies have constraints here
            # If you can go bigger than this great - but I would try not to go much smaller if you can
            # I use https://www.davidc.net/sites/default/subnets/subnets.html to me work out the CIDRs
            cidr="10.0.0.0/22",
            subnet_configuration=[
                # 3 x Public Subnets (1 per AZ) with 64 IPs each for our ALBs and NATs
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC,
                    name="Public",
                    cidr_mask=26
                ), 
                # 3 x Private Subnets (1 per AZ) with 256 IPs each for our Nodes and Pods
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE,
                    name="Private",
                    cidr_mask=24
                )
            ]
        )   
        #eks_vpc = ec2.Vpc.from_lookup(self, 'VPC', vpc_name="VPC")

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

        # Create the cluster-addons namespace
        # It also is an example of deploying a Kubernetes Manifest (need to convert to JSON) in CDK
        # if you would prefer to do that intead of use Flux to do GitOps with your cluster
        cluster_addon_namespace = eks_cluster.add_manifest("ClusterAddonNamespace", {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "cluster-addons"
            }
        })

        # Create the mapped AWS IAM Roles and Kubernetes Service Accounts for IRSA
        # For more info see https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html

        # AWS Load Balancer Controller
        alb_service_account = eks_cluster.add_service_account(
            "aws-load-balancer-controller",
            name="aws-load-balancer-controller",
            namespace="cluster-addons"
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
            namespace="cluster-addons"
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
            namespace="cluster-addons"
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
            namespace="cluster-addons"
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
            namespace="cluster-addons"
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
            namespace="cluster-addons",
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
            namespace="cluster-addons",
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
            namespace="cluster-addons"
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
            namespace="cluster-addons",
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
            namespace="cluster-addons",
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
                "namespace": "cluster-addons",
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
        awsebscsichart = eks_cluster.add_helm_chart(
            "aws-ebs-csi-driver",
            chart="aws-ebs-csi-driver",
            version="0.9.14",
            release="awsebscsidriver-0-9-14",
            repository="https://kubernetes-sigs.github.io/aws-ebs-csi-driver",
            namespace="cluster-addons",
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
        awsefscsichart = eks_cluster.add_helm_chart(
            "aws-efs-csi-driver",
            chart="aws-efs-csi-driver",
            version="1.1.1",
            release="awsefscsidriver-1-1-1",
            repository="https://kubernetes-sigs.github.io/aws-efs-csi-driver/",
            namespace="cluster-addons",
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
            namespace="cluster-addons",
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
            namespace="cluster-addons",
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
            namespace="cluster-addons"
        )

        # The namespace must exist before the service accounts can be created there
        alb_service_account.node.add_dependency(cluster_addon_namespace)
        externaldns_service_account.node.add_dependency(cluster_addon_namespace)
        fluentbit_service_account.node.add_dependency(cluster_addon_namespace)

        # Gatekeeper being an admission controller needs to be deployed last to not interfere
        gatekeeper_chart.node.add_dependency(metricsserver_chart)
        gatekeeper_chart.node.add_dependency(clusterautoscaler_chart)
        gatekeeper_chart.node.add_dependency(awsebscsichart)
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


app = core.App()
# Note that if we didn't pass through the ACCOUNT and REGION from these environment variables that
# it won't let us create 3 AZs and will only create a max of 2 - even when we ask for 3 in eks_vpc
eks_cluster_stack = EKSClusterStack(app, "EKSClusterStack", env=core.Environment(
    account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),
    region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])))
app.synth()