# Windows Installation Guide for Zphisher with ngrok

This guide will help you install and configure Zphisher with ngrok on Windows systems.

## 🚀 Quick Start

### Option 1: Automatic Installation (Recommended)

1. **Run the PowerShell script** (as Administrator):
   ```powershell
   # Right-click install_ngrok_windows.ps1 and select "Run with PowerShell"
   # Or run from Command Prompt:
   powershell -ExecutionPolicy Bypass -File install_ngrok_windows.ps1
   ```

2. **Or run the batch file**:
   ```cmd
   # Double-click install_ngrok_windows.bat
   # Or run from Command Prompt:
   install_ngrok_windows.bat
   ```

### Option 2: Manual Installation

1. **Download ngrok**:
   - Go to https://ngrok.com/download
   - Download the Windows version
   - Extract the zip file

2. **Install ngrok**:
   - Copy `ngrok.exe` to a directory (e.g., `C:\ngrok\`)
   - Add that directory to your PATH environment variable

## 🔧 Configuration

### Setting up ngrok Authentication (Recommended)

1. **Sign up for ngrok**:
   - Go to https://ngrok.com
   - Create a free account
   - Get your auth token from the dashboard

2. **Configure ngrok**:
   ```cmd
   ngrok authtoken YOUR_TOKEN_HERE
   ```

### Adding ngrok to PATH

1. **Open System Properties**:
   - Press `Win + Pause/Break`
   - Or right-click "This PC" → Properties → Advanced system settings

2. **Edit Environment Variables**:
   - Click "Environment Variables"
   - Under "System variables", find "Path"
   - Click "Edit"

3. **Add ngrok directory**:
   - Click "New"
   - Add the directory containing `ngrok.exe` (e.g., `C:\ngrok\`)
   - Click "OK" on all dialogs

4. **Restart your terminal**:
   - Close and reopen Command Prompt/PowerShell
   - Test with: `ngrok version`

## 🎯 Using Zphisher

### Starting the Application

1. **Start the backend**:
   ```cmd
   cd backend
   python app.py
   ```

2. **Start the frontend** (in a new terminal):
   ```cmd
   cd frontend
   npm run dev
   ```

3. **Open the application**:
   - Go to http://localhost:5173
   - Navigate to the Zphisher tool

### Using Zphisher with ngrok

1. **Select ngrok tunnel**:
   - In the Zphisher tool, select "ngrok" as the tunnel type
   - If ngrok is not available, click "Install ngrok"

2. **Choose a template**:
   - Select your desired phishing template
   - Popular options: Facebook, Google, Microsoft

3. **Start the campaign**:
   - Click "Start Session"
   - Wait for the tunnel to establish
   - Copy the generated phishing URL

## 🔍 Troubleshooting

### ngrok Not Found

**Problem**: `'ngrok' is not recognized as an internal or external command`

**Solutions**:
1. **Check PATH**: Ensure ngrok directory is in your PATH
2. **Restart terminal**: Close and reopen Command Prompt
3. **Manual installation**: Download from https://ngrok.com/download

### Permission Errors

**Problem**: Access denied when installing ngrok

**Solutions**:
1. **Run as Administrator**: Right-click PowerShell/Command Prompt → "Run as administrator"
2. **Use user directory**: Install to `%USERPROFILE%\ngrok\` instead of Program Files

### Firewall Issues

**Problem**: ngrok tunnel fails to establish

**Solutions**:
1. **Allow ngrok in firewall**: Windows Defender may block ngrok
2. **Check antivirus**: Temporarily disable antivirus to test
3. **Use localhost.run**: As alternative tunnel option

### SSH Not Available

**Problem**: localhost.run tunnel not working

**Solutions**:
1. **Install OpenSSH**: Windows 10/11 has built-in SSH client
2. **Enable SSH**: Go to Settings → Apps → Optional features → Add feature → OpenSSH Client
3. **Use ngrok**: Switch to ngrok tunnel instead

## 📋 System Requirements

- **Windows 10/11** (Windows 7/8 may work with limitations)
- **Python 3.7+** (for backend)
- **Node.js 14+** (for frontend)
- **Internet connection** (for ngrok tunnels)

## 🔒 Security Notes

- **Educational use only**: Zphisher is for educational and authorized testing
- **Legal compliance**: Ensure you have permission to test targets
- **Secure environment**: Use in isolated testing environment
- **Token security**: Keep your ngrok auth token secure

## 📞 Support

If you encounter issues:

1. **Check logs**: Look at backend console output for errors
2. **Verify dependencies**: Run `check_zphisher_deps.sh` (Git Bash) or `install_ngrok_windows.ps1`
3. **Test ngrok**: Run `ngrok version` to verify installation
4. **Alternative tunnels**: Try localhost.run if ngrok fails

## 🎉 Success!

Once everything is working:

- ✅ ngrok is installed and in PATH
- ✅ Zphisher backend is running
- ✅ Frontend is accessible
- ✅ You can create phishing campaigns with public URLs

Happy testing! 🚀 