#!/bin/bash

echo "🔍 Checking Zphisher dependencies..."

# Check if ngrok is installed
if command -v ngrok &> /dev/null; then
    echo "✅ ngrok is installed"
    ngrok version
else
    echo "❌ ngrok is not installed"
    echo "📦 Installing ngrok..."
    
    # Detect OS and install ngrok
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        echo "Installing ngrok for Linux..."
        curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
        echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
        sudo apt update
        sudo apt install ngrok -y
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo "Installing ngrok for macOS..."
        brew install ngrok/ngrok/ngrok
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
        # Windows (Git Bash, Cygwin, or Windows)
        echo "Installing ngrok for Windows..."
        
        # Download ngrok for Windows
        curl -L -o ngrok.zip https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-windows-amd64.zip
        
        # Extract ngrok
        unzip ngrok.zip
        rm ngrok.zip
        
        # Move to a directory in PATH
        if [[ -f "ngrok.exe" ]]; then
            # Try to move to a common location
            if [[ -d "/c/Program Files" ]]; then
                mkdir -p "/c/Program Files/ngrok"
                mv ngrok.exe "/c/Program Files/ngrok/"
                echo "ngrok installed to: C:\\Program Files\\ngrok\\ngrok.exe"
                echo "Please add C:\\Program Files\\ngrok to your PATH environment variable"
            elif [[ -d "/c/Users" ]]; then
                mkdir -p "/c/Users/$USER/ngrok"
                mv ngrok.exe "/c/Users/$USER/ngrok/"
                echo "ngrok installed to: C:\\Users\\$USER\\ngrok\\ngrok.exe"
                echo "Please add C:\\Users\\$USER\\ngrok to your PATH environment variable"
            else
                echo "ngrok.exe extracted to current directory"
                echo "Please move it to a directory in your PATH"
            fi
        else
            echo "❌ Failed to extract ngrok.exe"
            exit 1
        fi
    else
        echo "❌ Unsupported OS: $OSTYPE"
        echo "Please install ngrok manually from https://ngrok.com/download"
        exit 1
    fi
    
    # Verify installation
    if command -v ngrok &> /dev/null; then
        echo "✅ ngrok installed successfully!"
        ngrok version
    else
        echo "⚠️  ngrok installed but not in PATH"
        echo "Please add the ngrok directory to your PATH environment variable"
    fi
fi

# Check if SSH is available
if command -v ssh &> /dev/null; then
    echo "✅ SSH is available"
else
    echo "❌ SSH is not available"
fi

# Check if Zphisher is available
if [ -f "backend/zphisher/zphisher.sh" ]; then
    echo "✅ Zphisher script found"
else
    echo "❌ Zphisher script not found"
fi

echo "🎯 Zphisher dependency check complete!"
echo ""
echo "To use ngrok with authentication (recommended):"
echo "1. Sign up at https://ngrok.com"
echo "2. Get your auth token from the dashboard"
echo "3. Run: ngrok authtoken YOUR_TOKEN"
echo ""
echo "To start Zphisher with ngrok:"
echo "1. Start the backend: cd backend && python app.py"
echo "2. Start the frontend: cd frontend && npm run dev"
echo "3. Open the Zphisher tool in the web interface" 