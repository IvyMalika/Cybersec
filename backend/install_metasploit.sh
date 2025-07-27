#!/bin/bash

# Metasploit Framework Installation Script
# This script installs Metasploit Framework on various Linux distributions

set -e

echo "=== Metasploit Framework Installation Script ==="
echo "Detecting operating system..."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS $VER"

# Function to install dependencies
install_dependencies() {
    echo "Installing dependencies..."
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        sudo apt update
        sudo apt install -y curl wget git build-essential libreadline-dev libssl-dev libpq5 libpq-dev libreadline5 libsqlite3-dev libpcap-dev openjdk-11-jdk libxml2-dev libxslt1-dev libgmp-dev zlib1g-dev
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        sudo yum update -y
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y curl wget git readline-devel openssl-devel postgresql-devel sqlite-devel libpcap-devel java-11-openjdk-devel libxml2-devel libxslt-devel gmp-devel zlib-devel
    else
        echo "Unsupported OS: $OS"
        exit 1
    fi
}

# Function to install Ruby
install_ruby() {
    echo "Installing Ruby..."
    
    # Install rbenv for Ruby version management
    if ! command -v rbenv &> /dev/null; then
        echo "Installing rbenv..."
        curl -fsSL https://github.com/rbenv/rbenv-installer/raw/master/bin/rbenv-installer | bash
        echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
        echo 'eval "$(rbenv init -)"' >> ~/.bashrc
        source ~/.bashrc
    fi
    
    # Install Ruby 3.0.6 (required for Metasploit)
    echo "Installing Ruby 3.0.6..."
    rbenv install 3.0.6
    rbenv global 3.0.6
    
    # Install bundler
    gem install bundler
}

# Function to install PostgreSQL
install_postgresql() {
    echo "Installing PostgreSQL..."
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        sudo apt install -y postgresql postgresql-contrib
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
        
        # Create msf user
        sudo -u postgres createuser -s msf
        sudo -u postgres createdb msf
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        sudo yum install -y postgresql postgresql-server postgresql-contrib
        sudo postgresql-setup initdb
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
        
        # Create msf user
        sudo -u postgres createuser -s msf
        sudo -u postgres createdb msf
    fi
}

# Function to install Metasploit Framework
install_metasploit() {
    echo "Installing Metasploit Framework..."
    
    # Clone Metasploit repository
    cd /opt
    sudo git clone https://github.com/rapid7/metasploit-framework.git
    sudo chown -R $USER:$USER /opt/metasploit-framework
    cd metasploit-framework
    
    # Install dependencies
    bundle install
    
    # Create symlinks
    sudo ln -sf /opt/metasploit-framework/msfconsole /usr/local/bin/msfconsole
    sudo ln -sf /opt/metasploit-framework/msfvenom /usr/local/bin/msfvenom
    sudo ln -sf /opt/metasploit-framework/msfdb /usr/local/bin/msfdb
    sudo ln -sf /opt/metasploit-framework/msfrpcd /usr/local/bin/msfrpcd
    sudo ln -sf /opt/metasploit-framework/msfupdate /usr/local/bin/msfupdate
    
    # Initialize database
    msfdb init
}

# Function to install using package manager (alternative method)
install_metasploit_package() {
    echo "Installing Metasploit Framework via package manager..."
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        # Add Metasploit repository
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
        chmod +x msfinstall
        sudo ./msfinstall
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        # For RHEL/CentOS, we'll use the source installation method
        echo "Using source installation for RHEL/CentOS..."
        install_metasploit
    fi
}

# Function to configure Metasploit
configure_metasploit() {
    echo "Configuring Metasploit Framework..."
    
    # Create msfconsole configuration
    mkdir -p ~/.msf4
    cat > ~/.msf4/config << EOF
# Metasploit Framework Configuration
# Database configuration
db_connect msf:msf@localhost/msf

# Console configuration
setg ConsoleLogging true
setg LogLevel 3

# Module configuration
setg EnableContextEncoding true
setg DisablePayloadHandler true
EOF

    # Initialize database
    msfdb init
    
    echo "Metasploit Framework configuration completed!"
}

# Function to test installation
test_installation() {
    echo "Testing Metasploit Framework installation..."
    
    if command -v msfconsole &> /dev/null; then
        echo "✓ msfconsole found"
        msfconsole --version
    else
        echo "✗ msfconsole not found"
        return 1
    fi
    
    if command -v msfvenom &> /dev/null; then
        echo "✓ msfvenom found"
    else
        echo "✗ msfvenom not found"
        return 1
    fi
    
    echo "Metasploit Framework installation test completed successfully!"
}

# Main installation process
main() {
    echo "Starting Metasploit Framework installation..."
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        echo "Please do not run this script as root"
        exit 1
    fi
    
    # Install dependencies
    install_dependencies
    
    # Install Ruby
    install_ruby
    
    # Install PostgreSQL
    install_postgresql
    
    # Try package installation first, fallback to source
    if ! install_metasploit_package; then
        echo "Package installation failed, trying source installation..."
        install_metasploit
    fi
    
    # Configure Metasploit
    configure_metasploit
    
    # Test installation
    test_installation
    
    echo ""
    echo "=== Metasploit Framework Installation Complete ==="
    echo "You can now use the following commands:"
    echo "  msfconsole - Start Metasploit console"
    echo "  msfvenom - Create payloads"
    echo "  msfdb - Database management"
    echo "  msfupdate - Update Metasploit"
    echo ""
    echo "To start Metasploit console, run: msfconsole"
}

# Run main function
main "$@" 