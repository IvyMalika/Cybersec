#!/bin/bash

# Sherlock Tool Installation Script
# This script installs Sherlock for username enumeration across social media platforms

echo "Installing Sherlock Username Enumeration Tool..."

# Update package list
sudo apt-get update

# Install required dependencies
echo "Installing dependencies..."
sudo apt-get install -y python3 python3-pip git curl

# Install Sherlock via pip
echo "Installing Sherlock via pip..."
pip3 install sherlock-project

# Alternative installation method if pip fails
if ! command -v sherlock &> /dev/null; then
    echo "Pip installation failed, trying git method..."
    
    # Clone Sherlock repository
    git clone https://github.com/sherlock-project/sherlock.git
    cd sherlock
    
    # Install Sherlock
    python3 -m pip install -e .
    
    # Clean up
    cd ..
    rm -rf sherlock
fi

# Verify installation
if command -v sherlock &> /dev/null; then
    echo "✅ Sherlock installed successfully!"
    echo "Sherlock version:"
    sherlock --version
else
    echo "❌ Sherlock installation failed!"
    echo "Please try manual installation:"
    echo "1. git clone https://github.com/sherlock-project/sherlock.git"
    echo "2. cd sherlock"
    echo "3. python3 -m pip install -e ."
fi

# Install additional Python dependencies
echo "Installing additional Python dependencies..."
pip3 install requests beautifulsoup4 aiohttp

echo "Installation complete!"
echo ""
echo "Usage examples:"
echo "sherlock username"
echo "sherlock username --site Twitter,Instagram,Facebook"
echo "sherlock username --output results.json --format json" 