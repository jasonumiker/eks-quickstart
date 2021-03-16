# First install Homebrew if you don't have it already with a:
# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install python - note you'll need to put /usr/local/bin higher in your PATH
# in .zschrc or .bash_profile instead of the built-in python2 in /usr/bin
brew install python
ln -s /usr/local/bin/python3 /usr/local/bin/python
ln -s /usr/local/bin/pip3 /usr/local/bin/pip
# Install Node & NPM
brew install nodejs
# Install kubectl
brew install kubectl
# Install the CDK
npm install -g aws-cdk
# Install fluxctl
brew install fluxctl
# Install Helm
brew install helm
# Install the AWS CLI
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /