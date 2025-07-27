# Social Engineer Toolkit (SET) Integration

This document describes the integration of the Social Engineer Toolkit (SET) into the Cybersecurity Platform.

## Overview

The Social Engineer Toolkit (SET) is a penetration testing framework designed specifically for social engineering. This integration provides a web-based interface to interact with SET through the cybersecurity platform, enabling various social engineering attacks and payload generation.

## Features

- **Spear-Phishing Attacks**: Targeted email-based social engineering attacks
- **Web Attack Vectors**: Credential harvesting through malicious websites
- **Payload Generation**: Create malicious payloads for multiple platforms
- **Mass Mailer**: Send bulk phishing emails
- **Infectious Media**: Create malicious USB drives and media
- **Arduino Attacks**: Hardware-based social engineering
- **QR Code Attacks**: Malicious QR code generation
- **PowerShell Attacks**: PowerShell-based payloads
- **Macro Attacks**: Office document macro attacks
- **Real-time Monitoring**: Live attack progress and statistics
- **Session Management**: Track and manage multiple attack sessions
- **Template System**: Pre-built attack templates
- **Reporting**: Detailed attack reports and analytics

## Installation

### Prerequisites

- Linux system (Ubuntu, Debian, CentOS, RHEL, Fedora)
- Python 3.7 or later
- Git
- Internet connection for downloading SET

### Automated Installation

Run the installation script:

```bash
cd backend
./install_set.sh
```

This script will:
1. Install all required dependencies (Python, Git, build tools)
2. Clone and install the latest version of SET
3. Configure SET for web-based access
4. Install additional tools (Metasploit Framework)
5. Create attack templates and payload templates
6. Set up desktop shortcuts and systemd service
7. Test the installation

### Manual Installation

If you prefer manual installation, follow these steps:

1. **Install Dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install -y git python3 python3-pip python3-venv curl wget unzip
   sudo apt install -y build-essential libssl-dev libffi-dev python3-dev
   sudo apt install -y nmap metasploit-framework
   
   # CentOS/RHEL/Fedora
   sudo yum update -y
   sudo yum install -y git python3 python3-pip curl wget unzip
   sudo yum install -y gcc openssl-devel libffi-devel python3-devel
   sudo yum install -y nmap
   ```

2. **Clone and Install SET**:
   ```bash
   cd /opt
   sudo git clone https://github.com/trustedsec/social-engineer-toolkit.git set
   cd set
   sudo python3 setup.py install
   
   # Create symlinks
   sudo ln -sf /opt/set/setoolkit /usr/local/bin/setoolkit
   sudo ln -sf /opt/set/se-toolkit /usr/local/bin/se-toolkit
   sudo chown -R $USER:$USER /opt/set
   ```

3. **Configure SET**:
   ```bash
   mkdir -p ~/.set
   # Create configuration file (see install script for full config)
   ```

## Backend Integration

### Files

- `backend/set_tool.py`: Main SET integration class
- `backend/app.py`: API endpoints for SET functionality
- `backend/install_set.sh`: Installation script

### API Endpoints

#### Check Installation Status
```
GET /api/tools/set/status
```
Returns the installation status and version information.

#### Get Available Attacks
```
GET /api/tools/set/attacks
```
Returns a list of available social engineering attacks.

#### Get Attack Templates
```
GET /api/tools/set/templates
```
Returns available attack templates for phishing campaigns.

#### Start Spear-Phishing Attack
```
POST /api/tools/set/attack/spear-phishing
```
Body:
```json
{
  "targets": [
    {
      "email": "target@example.com",
      "name": "John Doe",
      "company": "Example Corp",
      "position": "Manager"
    }
  ],
  "payload_type": "windows",
  "email_template": "gmail_phishing",
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_username": "your-email@gmail.com",
  "smtp_password": "your-password"
}
```

#### Start Web Attack
```
POST /api/tools/set/attack/web-attack
```
Body:
```json
{
  "target_url": "https://example.com",
  "port": 80,
  "ssl": false,
  "website_template": "default"
}
```

#### Start Payload Generation
```
POST /api/tools/set/attack/payload-generation
```
Body:
```json
{
  "payload_type": "windows",
  "lhost": "192.168.1.100",
  "lport": 4444,
  "encoder": "shikata_ga_nai",
  "iterations": 1,
  "output_dir": "/tmp/set_payloads"
}
```

#### Get Session Status
```
GET /api/tools/set/session/{session_id}/status
```
Returns the current status and progress of an attack session.

#### Stop Session
```
POST /api/tools/set/session/{session_id}/stop
```
Stops an active attack session.

#### Get All Sessions
```
GET /api/tools/set/sessions
```
Returns all active and completed attack sessions.

#### Generate Report
```
POST /api/tools/set/session/{session_id}/report
```
Body:
```json
{
  "format": "html"
}
```
Generates a detailed report for an attack session.

## Frontend Integration

### Files

- `frontend/src/components/Tools/SETTool.tsx`: Main SET UI component
- `frontend/src/App.tsx`: Route configuration
- `frontend/src/components/Layout/AppLayout.tsx`: Navigation menu

### Features

1. **Multi-Tab Interface**:
   - Spear Phishing configuration
   - Web attack setup
   - Payload generation
   - Session management

2. **Target Management**:
   - Add/remove targets
   - Target information (email, name, company, position)
   - Bulk target import

3. **Attack Configuration**:
   - Email template selection
   - Payload type selection
   - SMTP configuration
   - Attack parameters

4. **Real-time Monitoring**:
   - Live attack progress
   - Statistics tracking
   - Session status updates

5. **Session Management**:
   - Start/stop attacks
   - Session history
   - Progress tracking
   - Results viewing

## Attack Types

### Spear-Phishing Attack Vector
- **Purpose**: Send targeted phishing emails with malicious payloads
- **Use Case**: Targeted social engineering campaigns
- **Features**: Email templates, payload attachment, SMTP configuration
- **Targets**: Specific individuals or organizations

### Web Attack Vector
- **Purpose**: Create malicious websites for credential harvesting
- **Use Case**: Credential theft and information gathering
- **Features**: Website cloning, credential harvesting, visitor tracking
- **Targets**: Web applications and login forms

### Infectious Media Generator
- **Purpose**: Create malicious USB drives and media
- **Use Case**: Physical social engineering attacks
- **Features**: Autorun payloads, USB drive preparation
- **Targets**: Physical access scenarios

### Harvester Attack
- **Purpose**: Harvest credentials from web forms
- **Use Case**: Credential collection and analysis
- **Features**: Form cloning, credential storage, real-time monitoring
- **Targets**: Login forms and authentication systems

### Mass Mailer Attack
- **Purpose**: Send bulk phishing emails
- **Use Case**: Large-scale social engineering campaigns
- **Features**: Bulk email sending, template system, tracking
- **Targets**: Large email lists

### Arduino-Based Attack Vector
- **Purpose**: Create malicious Arduino payloads
- **Use Case**: Hardware-based social engineering
- **Features**: Arduino programming, hardware integration
- **Targets**: IoT devices and embedded systems

### Wireless Access Point Attack
- **Purpose**: Create rogue access points
- **Use Case**: Network-based social engineering
- **Features**: AP creation, traffic interception, credential capture
- **Targets**: Wireless networks and users

### QR Code Generator Attack
- **Purpose**: Create malicious QR codes
- **Use Case**: Mobile-based social engineering
- **Features**: QR code generation, mobile payloads
- **Targets**: Mobile devices and users

### PowerShell Attack Vector
- **Purpose**: Create PowerShell-based payloads
- **Use Case**: Windows-based social engineering
- **Features**: PowerShell scripting, Windows integration
- **Targets**: Windows systems

### Macro Attack Vector
- **Purpose**: Create malicious Office macros
- **Use Case**: Document-based social engineering
- **Features**: Office macro creation, document embedding
- **Targets**: Office documents and users

## Payload Types

### Windows Payloads
- **Reverse Shell**: Command and control over Windows systems
- **Keylogger**: Keystroke logging and monitoring
- **Screenshot**: Screen capture and surveillance
- **File Stealer**: Data exfiltration capabilities

### Linux Payloads
- **Reverse Shell**: Command and control over Linux systems
- **Backdoor**: Persistent access to Linux systems
- **Rootkit**: Privilege escalation and persistence

### macOS Payloads
- **Reverse Shell**: Command and control over macOS systems
- **Keylogger**: Keystroke logging for macOS
- **Application Bundle**: Malicious application creation

### Android Payloads
- **Meterpreter**: Mobile command and control
- **Spyware**: Mobile surveillance and data collection
- **APK**: Malicious Android application creation

## Email Templates

### Gmail Phishing
- **Subject**: "Gmail Security Alert - Action Required"
- **Sender**: noreply@gmail.com
- **Target**: Gmail users
- **Purpose**: Credential harvesting

### LinkedIn Phishing
- **Subject**: "LinkedIn Security Update Required"
- **Sender**: security@linkedin.com
- **Target**: LinkedIn users
- **Purpose**: Professional credential theft

### Bank Phishing
- **Subject**: "Important: Your Bank Account Has Been Locked"
- **Sender**: security@bank.com
- **Target**: Banking customers
- **Purpose**: Financial credential theft

### Facebook Phishing
- **Subject**: "Facebook Account Suspended"
- **Sender**: security@facebook.com
- **Target**: Facebook users
- **Purpose**: Social media credential theft

## Usage

### Starting the Backend

1. Ensure SET is installed
2. Start the backend server:
   ```bash
   cd backend
   python3 app.py
   ```

### Accessing the Tool

1. Log in to the cybersecurity platform
2. Navigate to "Tools" → "Social Engineer Toolkit"
3. Choose your attack type:
   - **Spear Phishing**: Configure targets and email templates
   - **Web Attacks**: Set up credential harvesting sites
   - **Payload Generation**: Create malicious payloads
4. Configure attack parameters
5. Start the attack
6. Monitor progress in real-time
7. Review results and generate reports

### Example Usage

1. **Spear-Phishing Campaign**:
   - Add targets with email addresses and names
   - Select email template (Gmail, LinkedIn, etc.)
   - Configure SMTP settings
   - Choose payload type (Windows, Linux, etc.)
   - Start attack and monitor results

2. **Web Attack Setup**:
   - Enter target URL to clone
   - Configure port and SSL settings
   - Start web server
   - Monitor for harvested credentials

3. **Payload Generation**:
   - Select target platform (Windows, Linux, macOS, Android)
   - Configure listener settings (LHOST, LPORT)
   - Choose encoder and iterations
   - Generate and download payloads

## Security Considerations

1. **Authorization**: Only admin and analyst roles can access SET tools
2. **Legal Compliance**: Ensure you have permission to test target systems
3. **Ethical Use**: Use only for authorized penetration testing
4. **Data Protection**: Secure storage of harvested data
5. **Audit Trail**: Maintain logs of all activities
6. **Target Validation**: Verify targets before attacking
7. **Resource Limits**: Prevent resource exhaustion
8. **Session Isolation**: Isolate attack sessions

## Statistics Tracking

### Email Statistics
- **Emails Sent**: Number of emails successfully sent
- **Emails Opened**: Number of emails opened by targets
- **Click Rate**: Percentage of emails with clicked links
- **Response Rate**: Percentage of targets who responded

### Web Attack Statistics
- **Visitors**: Number of unique visitors to malicious site
- **Credentials Harvested**: Number of credentials captured
- **Session Duration**: Average time spent on site
- **Bounce Rate**: Percentage of immediate exits

### Payload Statistics
- **Payloads Created**: Number of payloads generated
- **Payloads Delivered**: Number of payloads successfully delivered
- **Execution Rate**: Percentage of payloads executed
- **Success Rate**: Percentage of successful compromises

## Reporting

### Attack Reports
- **Executive Summary**: High-level attack overview
- **Technical Details**: Detailed attack methodology
- **Statistics**: Comprehensive attack statistics
- **Recommendations**: Security improvement suggestions
- **Timeline**: Chronological attack events

### Vulnerability Reports
- **Risk Assessment**: Vulnerability risk levels
- **Impact Analysis**: Potential business impact
- **Remediation Steps**: Specific mitigation actions
- **Testing Results**: Attack success/failure rates

## Troubleshooting

### Common Issues

1. **SET not found**:
   - Ensure installation completed successfully
   - Check PATH environment variable
   - Verify symlinks are created correctly

2. **Python dependencies missing**:
   - Install required Python packages
   - Check Python version compatibility
   - Verify virtual environment setup

3. **SMTP configuration issues**:
   - Verify SMTP server settings
   - Check authentication credentials
   - Test SMTP connection manually

4. **Payload generation failures**:
   - Verify listener configuration
   - Check network connectivity
   - Validate payload parameters

### Debugging

1. **Check installation**:
   ```bash
   setoolkit --version
   se-toolkit --version
   ```

2. **Test SET functionality**:
   ```bash
   setoolkit
   # Navigate through SET menu
   ```

3. **Check configuration**:
   ```bash
   cat ~/.set/config.set
   ```

4. **Verify API access**:
   ```bash
   curl http://localhost:5000/api/tools/set/status
   ```

## Updates

To update SET:

1. **Update SET repository**:
   ```bash
   cd /opt/set
   sudo git pull origin master
   sudo python3 setup.py install
   ```

2. **Update dependencies**:
   ```bash
   pip3 install --upgrade set
   ```

3. **Update templates**:
   ```bash
   # Manually update templates in ~/.set/templates/
   ```

## Contributing

To add new features or fix issues:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This integration is part of the Cybersecurity Platform and follows the same licensing terms.

## Additional Resources

- [SET Official Documentation](https://github.com/trustedsec/social-engineer-toolkit)
- [SET Wiki](https://github.com/trustedsec/social-engineer-toolkit/wiki)
- [Social Engineering Resources](https://www.social-engineer.org/)
- [Penetration Testing Guide](https://www.pentest-standard.org/)

## Legal Notice

**IMPORTANT**: The Social Engineer Toolkit is designed for educational and authorized penetration testing purposes only. Users must ensure they have explicit permission before testing any systems or networks. Unauthorized use may violate laws and regulations. Always follow ethical guidelines and legal requirements when using this tool. 