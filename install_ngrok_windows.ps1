# PowerShell script to install ngrok on Windows
Write-Host "🔍 Checking Zphisher dependencies for Windows..." -ForegroundColor Green

# Check if ngrok is already installed
try {
    $ngrokVersion = & ngrok version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ ngrok is already installed" -ForegroundColor Green
        Write-Host $ngrokVersion
        exit 0
    }
} catch {
    # ngrok not found, continue with installation
}

Write-Host "❌ ngrok is not installed" -ForegroundColor Red
Write-Host "📦 Installing ngrok for Windows..." -ForegroundColor Yellow

# Create temporary directory
$tempDir = Join-Path $env:TEMP "ngrok_install"
if (!(Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}
Set-Location $tempDir

# Download ngrok
Write-Host "Downloading ngrok..." -ForegroundColor Yellow
try {
    $ngrokUrl = "https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-windows-amd64.zip"
    $zipPath = Join-Path $tempDir "ngrok.zip"
    Invoke-WebRequest -Uri $ngrokUrl -OutFile $zipPath -UseBasicParsing
    
    if (!(Test-Path $zipPath)) {
        throw "Failed to download ngrok"
    }
} catch {
    Write-Host "❌ Failed to download ngrok: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Extract ngrok
Write-Host "Extracting ngrok..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
    $ngrokExe = Join-Path $tempDir "ngrok.exe"
    
    if (!(Test-Path $ngrokExe)) {
        throw "Failed to extract ngrok.exe"
    }
} catch {
    Write-Host "❌ Failed to extract ngrok: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Try to install to a directory in PATH
$installSuccess = $false
$installPaths = @(
    "C:\Program Files\ngrok",
    "$env:LOCALAPPDATA\ngrok",
    "$env:USERPROFILE\ngrok"
)

foreach ($path in $installPaths) {
    try {
        if (!(Test-Path $path)) {
            New-Item -ItemType Directory -Path $path | Out-Null
        }
        
        $destPath = Join-Path $path "ngrok.exe"
        Copy-Item $ngrokExe $destPath -Force
        
        Write-Host "✅ ngrok installed to: $destPath" -ForegroundColor Green
        Write-Host "Please add this directory to your PATH environment variable:" -ForegroundColor Yellow
        Write-Host "  $path" -ForegroundColor Cyan
        
        $installSuccess = $true
        break
    } catch {
        Write-Host "Failed to install to $path : $($_.Exception.Message)" -ForegroundColor Red
        continue
    }
}

# Clean up
try {
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $ngrokExe -Force -ErrorAction SilentlyContinue
} catch {
    # Ignore cleanup errors
}

# Return to original directory
Set-Location $PSScriptRoot

if ($installSuccess) {
    Write-Host ""
    Write-Host "🎯 ngrok installation completed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To add ngrok to PATH permanently:" -ForegroundColor Yellow
    Write-Host "1. Open System Properties (Win + Pause/Break)" -ForegroundColor White
    Write-Host "2. Click 'Environment Variables'" -ForegroundColor White
    Write-Host "3. Edit 'Path' variable" -ForegroundColor White
    Write-Host "4. Add the ngrok directory path" -ForegroundColor White
    Write-Host "5. Click OK and restart your terminal" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "⚠️  ngrok downloaded but not added to PATH" -ForegroundColor Yellow
    Write-Host "Please manually add the ngrok directory to your PATH" -ForegroundColor Red
}

# Check SSH availability
Write-Host ""
Write-Host "Checking SSH availability..." -ForegroundColor Yellow
try {
    $sshVersion = & ssh -V 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ SSH is available" -ForegroundColor Green
    } else {
        Write-Host "❌ SSH is not available" -ForegroundColor Red
        Write-Host "Note: SSH is required for localhost.run tunnel" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ SSH is not available" -ForegroundColor Red
    Write-Host "Note: SSH is required for localhost.run tunnel" -ForegroundColor Yellow
}

# Check Zphisher availability
Write-Host ""
Write-Host "Checking Zphisher availability..." -ForegroundColor Yellow
if (Test-Path "backend\zphisher\zphisher.sh") {
    Write-Host "✅ Zphisher script found" -ForegroundColor Green
} else {
    Write-Host "❌ Zphisher script not found" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎯 Zphisher dependency check complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To use ngrok with authentication (recommended):" -ForegroundColor Yellow
Write-Host "1. Sign up at https://ngrok.com" -ForegroundColor White
Write-Host "2. Get your auth token from the dashboard" -ForegroundColor White
Write-Host "3. Run: ngrok authtoken YOUR_TOKEN" -ForegroundColor White
Write-Host ""
Write-Host "To start Zphisher with ngrok:" -ForegroundColor Yellow
Write-Host "1. Start the backend: cd backend && python app.py" -ForegroundColor White
Write-Host "2. Start the frontend: cd frontend && npm run dev" -ForegroundColor White
Write-Host "3. Open the Zphisher tool in the web interface" -ForegroundColor White
Write-Host ""

Read-Host "Press Enter to continue" 