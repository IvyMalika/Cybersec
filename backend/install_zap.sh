#!/bin/bash

# OWASP ZAP Installation Script
# This script installs OWASP ZAP on various Linux distributions

set -e

echo "=== OWASP ZAP Installation Script ==="
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
        sudo apt install -y curl wget unzip default-jre default-jdk
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        sudo yum update -y
        sudo yum install -y curl wget unzip java-11-openjdk java-11-openjdk-devel
    else
        echo "Unsupported OS: $OS"
        exit 1
    fi
}

# Function to download and install ZAP
install_zap() {
    echo "Installing OWASP ZAP..."
    
    # Create ZAP directory
    sudo mkdir -p /opt/zap
    cd /opt
    
    # Download latest ZAP
    echo "Downloading OWASP ZAP..."
    ZAP_VERSION=$(curl -s https://api.github.com/repos/zaproxy/zaproxy/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
    
    echo "Downloading ZAP version: $ZAP_VERSION"
    sudo wget -O zap.tar.gz "$ZAP_URL"
    
    # Extract ZAP
    echo "Extracting ZAP..."
    sudo tar -xzf zap.tar.gz
    sudo mv ZAP_* zap
    sudo chown -R $USER:$USER /opt/zap
    
    # Create symlinks
    sudo ln -sf /opt/zap/zap.sh /usr/local/bin/zap.sh
    sudo ln -sf /opt/zap/zap-cli /usr/local/bin/zap-cli
    sudo ln -sf /opt/zap/zap-baseline.py /usr/local/bin/zap-baseline.py
    
    # Clean up
    sudo rm -f zap.tar.gz
    
    echo "OWASP ZAP installed successfully!"
}

# Function to configure ZAP
configure_zap() {
    echo "Configuring OWASP ZAP..."
    
    # Create ZAP configuration directory
    mkdir -p ~/.ZAP
    
    # Create basic configuration
    cat > ~/.ZAP/zap.conf << EOF
# OWASP ZAP Configuration
# API Configuration
api.addrs.addr.name=.*
api.addrs.addr.regex=true
api.key=
api.incaddr.name=.*
api.incaddr.regex=true

# Proxy Configuration
proxy.ip=0.0.0.0
proxy.port=8080

# Scanner Configuration
scanner.threadPerHost=2
scanner.maxThreads=10

# Spider Configuration
spider.thread=2
spider.maxDepth=5

# Alert Configuration
alert.risk.levels=High,Medium,Low,Informational
alert.confidence.levels=High,Medium,Low,False_Positive
EOF

    echo "OWASP ZAP configuration completed!"
}

# Function to test installation
test_installation() {
    echo "Testing OWASP ZAP installation..."
    
    if command -v zap.sh &> /dev/null; then
        echo "✓ zap.sh found"
        zap.sh -version
    else
        echo "✗ zap.sh not found"
        return 1
    fi
    
    if command -v zap-cli &> /dev/null; then
        echo "✓ zap-cli found"
        zap-cli --version
    else
        echo "✗ zap-cli not found"
        return 1
    fi
    
    if command -v zap-baseline.py &> /dev/null; then
        echo "✓ zap-baseline.py found"
    else
        echo "✗ zap-baseline.py not found"
        return 1
    fi
    
    echo "OWASP ZAP installation test completed successfully!"
}

# Function to install ZAP via package manager (alternative method)
install_zap_package() {
    echo "Installing OWASP ZAP via package manager..."
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        # Add ZAP repository
        echo "deb https://zaproxy.jfrog.io/artifactory/zap-deb/ stable main" | sudo tee /etc/apt/sources.list.d/zap.list
        wget -qO - https://zaproxy.jfrog.io/artifactory/api/gpg/key/public | sudo apt-key add -
        sudo apt update
        sudo apt install -y zaproxy
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        # For RHEL/CentOS, we'll use the manual installation method
        echo "Using manual installation for RHEL/CentOS..."
        install_zap
    fi
}

# Function to create desktop shortcut
create_desktop_shortcut() {
    echo "Creating desktop shortcut..."
    
    cat > ~/Desktop/OWASP-ZAP.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=OWASP ZAP
Comment=OWASP Zed Attack Proxy
Exec=/opt/zap/zap.sh
Icon=/opt/zap/zap.ico
Terminal=false
Categories=Security;Development;
EOF

    chmod +x ~/Desktop/OWASP-ZAP.desktop
    echo "Desktop shortcut created!"
}

# Function to create systemd service
create_systemd_service() {
    echo "Creating systemd service..."
    
    sudo tee /etc/systemd/system/zap.service > /dev/null << EOF
[Unit]
Description=OWASP ZAP Daemon
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/zap
ExecStart=/opt/zap/zap.sh -daemon -port 8080 -config api.key= -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable zap.service
    
    echo "Systemd service created and enabled!"
}

# Main installation process
main() {
    echo "Starting OWASP ZAP installation..."
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        echo "Please do not run this script as root"
        exit 1
    fi
    
    # Install dependencies
    install_dependencies
    
    # Try package installation first, fallback to manual
    if ! install_zap_package; then
        echo "Package installation failed, trying manual installation..."
        install_zap
    fi
    
    # Configure ZAP
    configure_zap
    
    # Create desktop shortcut
    create_desktop_shortcut
    
    # Create systemd service
    create_systemd_service
    
    # Test installation
    test_installation
    
    echo ""
    echo "=== OWASP ZAP Installation Complete ==="
    echo "You can now use the following commands:"
    echo "  zap.sh - Start ZAP GUI"
    echo "  zap.sh -daemon -port 8080 - Start ZAP daemon"
    echo "  zap-cli --help - ZAP command line interface"
    echo "  zap-baseline.py --help - ZAP baseline scanning"
    echo ""
    echo "To start ZAP GUI, run: zap.sh"
    echo "To start ZAP daemon, run: sudo systemctl start zap"
    echo ""
    echo "ZAP will be available at: http://localhost:8080"
}

# Run main function
main "$@" 