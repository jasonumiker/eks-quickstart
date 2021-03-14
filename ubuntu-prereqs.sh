#!/bin/bash

# Script to install prerequistes on Ubuntu 20.04.2 LTS (including via Windows 10's WSL) 

# Install Node & Pyton
apt update -y
apt upgrade -y
apt install nodejs npm python3-pip unzip -y
ln -s /usr/bin/pip3 /usr/bin/pip
ln -s /usr/bin/python3 /usr/bin/python

# Install the latest AWS CLI
cd /tmp
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

# Install kubectl from the deb repo
apt-get install -y apt-transport-https ca-certificates curl
curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y kubectl

# Install the CDK
npm install -g aws-cdk

# Install the fluxctl
cd /tmp
wget -O fluxctl https://github.com/fluxcd/flux/releases/download/1.21.2/fluxctl_linux_amd64
chmod +x fluxctl
mv fluxctl /usr/local/bin

# Install Helm
cd /tmp
wget -O helm.tgz https://get.helm.sh/helm-v3.5.3-linux-amd64.tar.gz
chmod +x linux-amd64/helm
mv linux-amd64/helm /usr/local/bin 