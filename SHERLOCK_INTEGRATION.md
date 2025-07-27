# Sherlock Tool Integration

## Overview
Sherlock is a powerful username enumeration tool that searches for usernames across social media platforms. This integration adds Sherlock functionality to your cybersecurity platform.

## Features
- **Username Enumeration**: Search for usernames across 300+ social media platforms
- **Platform Selection**: Choose specific platforms to search
- **Real-time Monitoring**: Track search progress in real-time
- **Results Management**: View and export search results
- **Session Management**: Manage multiple search sessions
- **Timeout Control**: Set custom timeout values

## Installation

### 1. Install Sherlock Tool
```bash
# Make the installation script executable
chmod +x backend/install_sherlock.sh

# Run the installation script
./backend/install_sherlock.sh
```

### 2. Verify Installation
```bash
# Check if sherlock is installed
sherlock --version

# Test with a sample username
sherlock testuser --site Twitter,Instagram
```

## API Endpoints

### Start Username Search
```http
POST /api/tools/sherlock/search
Content-Type: application/json
Authorization: Bearer <token>

{
  "username": "target_username",
  "platforms": ["Twitter", "Instagram", "Facebook"],
  "timeout": 300
}
```

### Get Session Status
```http
GET /api/tools/sherlock/status/<session_id>
Authorization: Bearer <token>
```

### Get All Sessions
```http
GET /api/tools/sherlock/sessions
Authorization: Bearer <token>
```

### Stop Session
```http
POST /api/tools/sherlock/stop/<session_id>
Authorization: Bearer <token>
```

### Get Available Platforms
```http
GET /api/tools/sherlock/platforms
Authorization: Bearer <token>
```

## Usage Examples

### Basic Search
```javascript
// Start a search for username "john_doe"
const response = await fetch('/api/tools/sherlock/search', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    username: 'john_doe'
  })
});

const session = await response.json();
console.log('Session ID:', session.session_id);
```

### Search Specific Platforms
```javascript
// Search only popular platforms
const response = await fetch('/api/tools/sherlock/search', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    username: 'john_doe',
    platforms: ['Twitter', 'Instagram', 'Facebook', 'LinkedIn'],
    timeout: 180
  })
});
```

### Monitor Search Progress
```javascript
// Poll for status updates
const pollStatus = async (sessionId) => {
  const response = await fetch(`/api/tools/sherlock/status/${sessionId}`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const status = await response.json();
  
  if (status.status === 'completed') {
    console.log('Found accounts:', status.results.filter(r => r.exists === 'yes'));
  } else if (status.status === 'running') {
    // Continue polling
    setTimeout(() => pollStatus(sessionId), 2000);
  }
};
```

## Frontend Component

The Sherlock tool is integrated into the frontend with a modern React component that provides:

- **Search Interface**: Enter username and select platforms
- **Real-time Progress**: See search progress with progress bars
- **Results Display**: View found accounts in a table format
- **Session Management**: View and manage previous searches
- **Platform Selection**: Choose specific platforms to search

## Security Considerations

### Rate Limiting
- Implement rate limiting to prevent abuse
- Set reasonable timeout values
- Monitor API usage

### Ethical Use
- Only search usernames you own or have permission to search
- Respect platform terms of service
- Use for legitimate security research only

### Privacy
- Log search activities for audit purposes
- Implement user authentication
- Secure API endpoints

## Configuration

### Environment Variables
```bash
# Sherlock tool path (optional)
SHERLOCK_PATH=/usr/local/bin/sherlock

# Default timeout (seconds)
SHERLOCK_TIMEOUT=300

# Rate limiting
SHERLOCK_RATE_LIMIT=10
```

### Database Tables
The tool uses existing database tables for logging:
- `jobs`: Track search jobs
- `results`: Store search results
- `activity_log`: Log user activities

## Troubleshooting

### Common Issues

1. **Sherlock not found**
   ```bash
   # Install manually
   pip3 install sherlock-project
   ```

2. **Permission denied**
   ```bash
   # Fix permissions
   sudo chmod +x backend/install_sherlock.sh
   ```

3. **Network timeouts**
   - Increase timeout value
   - Check network connectivity
   - Use VPN if needed

4. **Platform not responding**
   - Some platforms may block automated requests
   - Use specific platform selection
   - Implement delays between requests

### Debug Mode
Enable debug logging in the backend:
```python
# In app.py
app.logger.setLevel(logging.DEBUG)
```

## Advanced Features

### Custom Platform Lists
Create custom platform lists for specific use cases:
```python
# In sherlock_tool.py
CUSTOM_PLATFORMS = {
    'social': ['Twitter', 'Instagram', 'Facebook'],
    'professional': ['LinkedIn', 'GitHub', 'StackOverflow'],
    'gaming': ['Steam', 'Discord', 'Twitch']
}
```

### Result Export
Export results in various formats:
```python
# Export to JSON
with open('results.json', 'w') as f:
    json.dump(results, f, indent=2)

# Export to CSV
import csv
with open('results.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['Platform', 'URL', 'Status'])
    for result in results:
        writer.writerow([result['name'], result['url_user'], result['exists']])
```

### Integration with Other Tools
Combine Sherlock with other OSINT tools:
- **Nmap**: Network reconnaissance
- **OSINT Gatherer**: Additional intelligence
- **Threat Intelligence**: Context analysis

## Contributing

To extend the Sherlock integration:

1. **Add New Platforms**: Update platform list in frontend
2. **Enhance Results**: Add more result fields
3. **Improve UI**: Add new visualization options
4. **Add Analytics**: Track search patterns and success rates

## License

This integration follows the same license as the main project. Sherlock tool itself is licensed under GPL-3.0.

## Support

For issues with the Sherlock integration:
1. Check the troubleshooting section
2. Review Sherlock documentation
3. Check system logs
4. Contact the development team 