#!/usr/bin/env bash
# exit on error
set -o errexit

# Install Python requirements
pip install -r requirements.txt

# Download and install Google Chrome for Linux
echo "Installing Google Chrome..."
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
apt-get update
apt-get install -y google-chrome-stable