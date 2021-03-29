# EKS Quickstart

This project is an example of how you can combine the AWS Cloud Development Kit (CDK) and the AWS Elastic Kubernetes Serivce (EKS) to quickly deploy a more complete and "production ready" Kubernetes environment on AWS.

## What does this QuickStart create for you:

1. (Optional) An appropriate VPC (/22 CDIR w/1024 IPs by default - though you can edit this in `eks_cluster.py`) with public and private subnets across three availabilty zones.
1. A new EKS cluster with:
    1. A dedicated new IAM role to create it from. The role that creates the cluster is a permanent, and rather hidden, full admin role that doesn't appear in nor is subject to the aws-auth config map. So, you want a dedicated role explicity for that purpose like CDK does for you here that you can then restrict access to assume unless you need it (e.g. you lock yourself out of the cluster with by making a mistake in the aws-auth configmap).
    1. A new Managed Node Group with 3 x m5.large instances spread across 3 Availability Zones.
1. (Optional) The AWS Load Balancer Controller (https://kubernetes-sigs.github.io/aws-load-balancer-controller) to allow you to seamlessly use ALBs for Ingress and NLB for Services.
1. (Optional) External DNS (https://github.com/kubernetes-sigs/external-dns) to allow you to automatically create/update Route53 entries to point your 'real' names at your Ingresses and Services.
1. (Optional) A new managed Amazon Elasticsearch Domain and an aws-for-fluent-bit DaemonSet (https://github.com/aws/aws-for-fluent-bit) to ship all your container logs there - including enriching them with the Kubernetes metadata using the kubernetes fluent-bit filter.
1. (Optional) (Temporarily until the AWS Managed Prometheus/Grafana are available) The kube-prometheus Operator (https://github.com/prometheus-operator/kube-prometheus) which gives you a Prometheus that will collect all your cluster metrics as well as a Grafana to visualise them.
    1. TODO: Add some initial alerts for sensible common items in the cluster via Prometheus/Alertmanager
1. (Optional) The AWS EBS CSI Driver (https://github.com/kubernetes-sigs/aws-ebs-csi-driver)
1. (Optional) The AWS EFS CSI Driver (https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html)
1. (Optional) A OPA Gatekeeper to enforce prevenetative secruity and operational policies (https://github.com/open-policy-agent/gatekeeper)
    1. TODO: Add some sensible initial policies to make our cluster 'secure by default'
1. (Optional) The cluster autoscaler (CA) (https://github.com/kubernetes/autoscaler)
1. (Optional) The metrics-server (required for the Horizontal Pod Autoscaler (HPA)) (https://github.com/kubernetes-sigs/metrics-server)
1. (Optional) The Calico Network Policy Provider (https://docs.aws.amazon.com/eks/latest/userguide/calico.html)
1. (Optional) The AWS Simple Systems Manager (SSM) agent

For each optional item there is a boolean at the top of `cluster-bootstrap\eks_cluster.py` that you flip to True/False

### Why Cloud Development Kit (CDK)?

The Cloud Development Kit is a tool where you can write infrastucture-as-code with 'actual' code (TypeScript, Python, C#, and Java). This takes these lanugages and 'compiles' them into a CloudFormation template for the AWS CloudFormation engine to then deploy and manage as stacks.

When you develop with the CDK you then don't edit the intermediate CloudFormation but let CDK regenerate it in reponse to changes in the upstream template.

What makes CDK uniquely good when it comes to our EKS Quickstart is:

* It handles the IAM Roles for Service Accounts (IRSA) rather elegantly and creates the IAM Roles and Policies, creates the service accounts and then maps them to each other.
* It has implemented custom CloudFormation resources with Lambda invoking kubectl and helm to deploy manifests and charts as part of the cluster provisioning.
    * Until we have Managed Add-On for the common things with EKS this can fill the gap and provision us a complete cluster with all the add-ons we need.

## Getting started

You can either deploy this from your machine or leverge CodeBuild. 

###  Deploy from CodeBuild
To use the CodeBuild CloudFormation Template:

1. Generate a personal access token on GitHub - https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token 
1. Edit `cluster-codebuild/EKSCodeBuildStack.template.json` to change Location to your GitHub repo/path
1. Run `aws codebuild import-source-credentials --server-type GITHUB --auth-type PERSONAL_ACCESS_TOKEN --token <token_value>` to provide your token to CodeBuild
1. Deploy `cluster-codebuild/EKSCodeBuildStack.template.json`
1. Go to the CodeBuild console, click on the Build project that starts with `EKSCodeBuild`, and then click the Start build button.
1. (Optional) You can click the Tail logs button to follow along with the build process

**_NOTE:_** This also enables a GitOps pattern where changes to the cluster-bootrap folder on the branch mentioned (main by default) will re-trigger this CodeBuild to do another `cdk deploy` via web hook.

### Deploy from your laptop
There are some prerequsistes you likely will need to install on the machine doing your environment bootstrapping including Node, Python, the AWS CLI, the CDK, fluxctl and Helm

#### Pre-requisites - Ubuntu 20.04.2 LTS (including via Windows 10's WSL)
Run `sudo ./ubuntu-prepreqs.sh`

#### Pre-requisites - Mac

1. Install Homebrew (https://brew.sh/)
1. Run `./mac-prereqs.sh`
1. Edit your `~/.zshrc` and/or your `~/.bash_profile` to put /usr/local/bin at the start of your PATH statement so that the brew things installed take precendence over the built-in often outdated options like python2.

#### Deploy from CDK locally

1. Make sure that you have your AWS CLI configured with administrative access to the AWS account in question (e.g. an `aws s3 ls` works)
    1. This can be via setting your access key and secret in your .aws folder via `aws configure` or in your environment variables by copy and pasting from AWS SSO etc.
1. Run `cd eks-quickstart/cluster-bootstrap`
1. Run `pip install -r requirements.txt` to install the required Python bits of the CDK
1. Run `export CDK_DEPLOY_REGION=ap-southeast-2` replacing ap-southeast-2 with your region of choice
1. Run `export CDK_DEPLOY_ACCOUNT=123456789123` replacing 123456789123 with your AWS account number
1. (Optional) If you want to make an existing IAM User or Role the cluster admin rather than creating a new one then edit `eks_cluster.py` and comment out the curernt cluster_admin_role and uncomment the one beneath it and fill in the ARN of the User/Role you'd like there.
1. (Only required the first time you use the CDK in this account) Run `cdk bootstrap` to create the S3 bucket where it puts the CDK puts its artifacts
1. (Only required the first time ES in VPC mode is used in this account) Run `aws iam create-service-linked-role --aws-service-name es.amazonaws.com`
1. Run `cdk deploy --require-approval never`
1. (Temporary until it is added to our Helm Chart - PR open) Run `kubectl edit configmap fluentbit-0-1-6-aws-for-fluent-bit --namespace=cluster-addons` and add the following to the bottom `Replace_Dots On`

## Deploy and set up a Bastion based on an EC2 instance running Code Server

If you set `deploy_bastion` to `True` in `eks_cluster.py` then the template will deploy an EC2 instance running [Code Server](https://github.com/cdr/code-server) which is Visual Studio Code but running in your browser.

The stack will have an Output with the address to the Bastion and the password for the web interface defaults to the Instance ID of the Bastion Instance (which you can get from the EC2 Console).

**_NOTE:_** Since this defaults to HTTP rather than HTTPS to accomodate accounts without a public Route 53 Zone and associated certificates that means that modern browsers won't allow you to paste with Ctrl-V. You can, however, paste with shift-insert (insert = fn + return on a Mac so shift-fn-return on one of those).

Here are a few things to familiarise yourself with the Bastion:

- Click the three dashes (I call it the hambuger menu) in the upper left corrner then click `Terminal` and then `New Terminal`.
- Run `kubectl get nodes` and see that we've already installed the tools for you and run the `aws eks update-kubeconfig` and it is all working
- Click the three dashes in the upper left then click View then Command Palette. In that box type Browser Preview and choose `Browser Preview: Open Preview`. This browser is running on the Instance in the private VPC and you can use this browser to reach Kibana and Grafana etc.

## Set up your Client VPN to access the environment

If you set `deploy_vpn` to `True` in `eks_cluster.py` then the template will deploy a Client VPN.

You'll also need to create client and server certificates and upload them to ACM by following these instructions - https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html#mutual. Then you update `ekscluster.py` with the certificate ARNs.

Once it has created your VPN you then need to configure the client:

1. Open the AWS VPC Console and go to the Client VPN Endpoints on the left panel
1. Click the Download Client Configuration button
1. Edit the downloaded file and add:
    1. A section at the bottom for the server cert in between <cert> and </cert>
    1. Then under that a section for the client private key between <key> and </key>
1. Install the AWS Client VPN Client - https://aws.amazon.com/vpn/client-vpn-download/
1. Create a new profile pointing it at that configuration file
1. Connect to the VPN

Once you are connected it is a split tunnel - meaning only the addresses in your EKS VPC will get routed through the VPN tunnel.

You then need to add the EKS cluster to your local kubeconfig by running the command in the clusterConfigCommand Output of the EKSClusterStack.

Then you should be able to run a `kubectl get all -A` and see everything running on your cluster.

## Allow access to the Elasticsearch and Kibana to query your logs

We put the Elasticsearch both in the VPC (i.e. not on the Internet) as well as in the same Security Group we use for controlling access to our EKS Control Plane. 

We did this so that when we put the Client VPN in that security group as well then it has access from a network perspective to *both* manage EKS and Elasticsearch/Kibana.

Since this ElasticSearch can only be reached from a network perspective if you are running within this VPC, or have private access to it via a VPN or DirectConnect, then it is not that risky to allow 'open access' to it - especially in a Proof of Concept (POC) environment.

In order to do this:

1. Go to the Amazon Elaticsearch Service within the AWS Console
1. Click on the Domain that starts with eksclus-
1. Click on the Actions button on top and choose Modify Access Policy
1. In the Domain access policy dropdown choose "Allow open access to the domain" and click Submit

### Connect to Kibana and do initial setup

1. Once that new access policy has applied click on the Kibana link on the Elasticsearch Domain's Overview Tab
1. Click "Explore on my own" in the Welcome page
1. Click "Connect to your Elasticsearch index" under "Use Elasticsearch Data"
1. Close the About index patterns box
1. Click the Create Index Pattern button
1. In the Index pattern name box enter `fluent-bit*` and click Next step
1. Pick @timestamp from the dropbown box and click Create index pattern
1. Then go back Home and click Discover

TODO: Walk through how to do a few basic things in Kibana with searching and dashboarding your logs.

## Checking out Grafana and the out-of-the-box metrics dashboards

TODO: Walk through how to get to the out-of-the-box metrics dashboards in Grafana

## Deploy some sample apps to explore our new Kubernetes environment and its features

TODO: Walk through deploying some apps that show off some of the cluster add-ons we've installed

## Upgrading your cluster

TODO: Walk through how to do an EKS Cluster to a new Kubernetes version and/or the Managed Node Group to the latest AMI upgrade via CDK

## Upgrading an add-on

TODO: Walk through how to upgrade an individual add-on manifest/chart via CDK

## Outstanding Issues

* The CDK currently doesn't support enabling the logs on the control plane - https://github.com/aws/aws-cdk/issues/4159. If it appears that will be the case for awhile will investigate other ways to automate that in this script such as a CloudFormation custom resource
* Investigate replacing the current instance ID password for the Bastion with something more secure such as generating a longer string and storing it in Secrets Manager
