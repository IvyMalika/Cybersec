# OWASP ZAP Integration

This document describes the integration of OWASP ZAP (Zed Attack Proxy) into the Cybersecurity Platform.

## Overview

OWASP ZAP is a free, open-source web application security scanner designed to help developers and security professionals find vulnerabilities in web applications. This integration provides a web-based interface to interact with ZAP through the cybersecurity platform.

## Features

- **Web Application Scanning**: Comprehensive vulnerability scanning for web applications
- **Multiple Scan Types**: Spider, Active, Full, and Baseline scanning options
- **Real-time Monitoring**: Live scan progress and vulnerability detection
- **Vulnerability Reporting**: Detailed vulnerability analysis and reporting
- **Session Management**: Track and manage multiple scan sessions
- **Risk Assessment**: Categorized vulnerability reporting by risk level

## Installation

### Prerequisites

- Linux system (Ubuntu, Debian, CentOS, RHEL, Fedora)
- Java 11 or later
- Internet connection for downloading ZAP

### Automated Installation

Run the installation script:

```bash
cd backend
./install_zap.sh
```

This script will:
1. Install all required dependencies (Java, curl, wget, unzip)
2. Download and install the latest version of OWASP ZAP
3. Configure ZAP for API access
4. Create desktop shortcuts and systemd service
5. Test the installation

### Manual Installation

If you prefer manual installation, follow these steps:

1. **Install Dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install -y curl wget unzip default-jre default-jdk
   
   # CentOS/RHEL/Fedora
   sudo yum update -y
   sudo yum install -y curl wget unzip java-11-openjdk java-11-openjdk-devel
   ```

2. **Download and Install ZAP**:
   ```bash
   cd /opt
   sudo mkdir -p zap
   cd zap
   
   # Download latest ZAP
   ZAP_VERSION=$(curl -s https://api.github.com/repos/zaproxy/zaproxy/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
   sudo wget -O zap.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
   
   # Extract and configure
   sudo tar -xzf zap.tar.gz
   sudo mv ZAP_*/* .
   sudo chown -R $USER:$USER /opt/zap
   
   # Create symlinks
   sudo ln -sf /opt/zap/zap.sh /usr/local/bin/zap.sh
   sudo ln -sf /opt/zap/zap-cli /usr/local/bin/zap-cli
   sudo ln -sf /opt/zap/zap-baseline.py /usr/local/bin/zap-baseline.py
   ```

3. **Configure ZAP**:
   ```bash
   mkdir -p ~/.ZAP
   cat > ~/.ZAP/zap.conf << EOF
   api.addrs.addr.name=.*
   api.addrs.addr.regex=true
   api.key=
   proxy.ip=0.0.0.0
   proxy.port=8080
   EOF
   ```

## Backend Integration

### Files

- `backend/zap_tool.py`: Main ZAP integration class
- `backend/app.py`: API endpoints for ZAP functionality
- `backend/install_zap.sh`: Installation script

### API Endpoints

#### Check Installation Status
```
GET /api/tools/zap/status
```
Returns the installation status and version information.

#### Get Available Scan Types
```
GET /api/tools/zap/scan-types
```
Returns a list of available scan types with descriptions.

#### Start Scan
```
POST /api/tools/zap/scan/start
```
Body:
```json
{
  "target_url": "https://example.com",
  "scan_type": "full",
  "options": {}
}
```

#### Get Session Status
```
GET /api/tools/zap/session/{session_id}/status
```
Returns the current status and progress of a scan session.

#### Stop Session
```
POST /api/tools/zap/session/{session_id}/stop
```
Stops an active scan session.

#### Get All Sessions
```
GET /api/tools/zap/sessions
```
Returns all active and completed scan sessions.

#### Get Vulnerability Summary
```
GET /api/tools/zap/session/{session_id}/vulnerabilities
```
Returns a vulnerability summary for a completed scan.

#### Generate Report
```
POST /api/tools/zap/session/{session_id}/report
```
Body:
```json
{
  "format": "html"
}
```
Generates a detailed report for a scan session.

## Frontend Integration

### Files

- `frontend/src/components/Tools/ZAPTool.tsx`: Main ZAP UI component
- `frontend/src/App.tsx`: Route configuration
- `frontend/src/components/Layout/AppLayout.tsx`: Navigation menu

### Features

1. **Scan Configuration Panel**:
   - Target URL input
   - Scan type selection
   - Custom options configuration

2. **Real-time Monitoring**:
   - Live scan progress
   - Real-time vulnerability detection
   - Session status updates

3. **Vulnerability Display**:
   - Risk-based categorization
   - Detailed vulnerability information
   - Evidence and solutions

4. **Session Management**:
   - Start/stop scan sessions
   - Session history
   - Progress tracking

## Scan Types

### Spider Scan
- **Purpose**: Crawl the website to discover pages and resources
- **Use Case**: Initial reconnaissance and site mapping
- **Speed**: Fast
- **Coverage**: Discovers URLs and resources

### Active Scan
- **Purpose**: Actively test for vulnerabilities by sending malicious requests
- **Use Case**: Deep vulnerability testing
- **Speed**: Slow (thorough)
- **Coverage**: Tests for specific vulnerabilities

### Full Scan
- **Purpose**: Complete spider and active scan combination
- **Use Case**: Comprehensive security assessment
- **Speed**: Very slow
- **Coverage**: Maximum coverage

### Baseline Scan
- **Purpose**: Quick passive scan for common vulnerabilities
- **Use Case**: Initial assessment
- **Speed**: Very fast
- **Coverage**: Basic vulnerability detection

## Usage

### Starting the Backend

1. Ensure OWASP ZAP is installed
2. Start the backend server:
   ```bash
   cd backend
   python3 app.py
   ```

### Accessing the Tool

1. Log in to the cybersecurity platform
2. Navigate to "Tools" → "OWASP ZAP Scanner"
3. Configure your scan:
   - Enter target URL
   - Select scan type
   - Configure any options
4. Click "Start Scan" to begin
5. Monitor the scan in real-time
6. Review vulnerability results

### Example Usage

1. **Basic Web Application Scan**:
   - Target: `https://example.com`
   - Scan Type: `spider`
   - Purpose: Discover pages and resources

2. **Comprehensive Security Assessment**:
   - Target: `https://example.com`
   - Scan Type: `full`
   - Purpose: Complete vulnerability assessment

3. **Quick Baseline Check**:
   - Target: `https://example.com`
   - Scan Type: `baseline`
   - Purpose: Quick security overview

## Vulnerability Categories

### High Risk
- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution
- Authentication Bypass
- Sensitive Data Exposure

### Medium Risk
- Cross-Site Request Forgery (CSRF)
- Information Disclosure
- Insecure Direct Object References
- Security Misconfiguration

### Low Risk
- Missing Security Headers
- Outdated Software
- Debug Information Disclosure
- Predictable Resource Location

### Informational
- Technology Information
- Directory Listing
- Server Information
- Cookie Attributes

## Security Considerations

1. **Authorization**: Only admin and analyst roles can access ZAP tools
2. **Target Validation**: All targets are validated before scanning
3. **Session Isolation**: Each scan session is isolated
4. **Resource Limits**: Scans have timeout limits to prevent resource exhaustion
5. **Legal Compliance**: Ensure you have permission to scan target applications

## Troubleshooting

### Common Issues

1. **ZAP not found**:
   - Ensure installation completed successfully
   - Check PATH environment variable
   - Verify symlinks are created correctly

2. **Java not found**:
   - Install Java 11 or later
   - Check JAVA_HOME environment variable
   - Verify Java installation

3. **API connection issues**:
   - Ensure ZAP daemon is running
   - Check firewall settings
   - Verify API configuration

4. **Permission denied**:
   - Ensure proper file permissions
   - Check user permissions for ZAP directory
   - Verify Java permissions

### Debugging

1. **Check installation**:
   ```bash
   zap.sh -version
   zap-cli --version
   ```

2. **Test ZAP daemon**:
   ```bash
   zap.sh -daemon -port 8080
   ```

3. **Check API access**:
   ```bash
   curl http://localhost:8080/JSON/core/view/version/
   ```

## Updates

To update OWASP ZAP:

1. **Download latest version**:
   ```bash
   cd /opt/zap
   sudo wget -O zap.tar.gz "https://github.com/zaproxy/zaproxy/releases/download/LATEST/ZAP_LATEST_Linux.tar.gz"
   sudo tar -xzf zap.tar.gz
   sudo mv ZAP_*/* .
   sudo chown -R $USER:$USER /opt/zap
   ```

2. **Update plugins**:
   ```bash
   zap.sh -addonupdate
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

- [OWASP ZAP Official Documentation](https://www.zaproxy.org/docs/)
- [ZAP API Documentation](https://www.zaproxy.org/docs/api/)
- [ZAP User Guide](https://www.zaproxy.org/docs/desktop/)
- [ZAP Command Line Interface](https://www.zaproxy.org/docs/desktop/cmdline/) 