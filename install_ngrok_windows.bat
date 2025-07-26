@echo off
echo 🔍 Checking Zphisher dependencies for Windows...

REM Check if ngrok is already installed
where ngrok >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ ngrok is already installed
    ngrok version
    goto :check_ssh
)

echo ❌ ngrok is not installed
echo 📦 Installing ngrok for Windows...

REM Create temporary directory
set "temp_dir=%TEMP%\ngrok_install"
if not exist "%temp_dir%" mkdir "%temp_dir%"
cd /d "%temp_dir%"

REM Download ngrok
echo Downloading ngrok...
powershell -Command "Invoke-WebRequest -Uri 'https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-windows-amd64.zip' -OutFile 'ngrok.zip'"
if not exist "ngrok.zip" (
    echo ❌ Failed to download ngrok
    goto :cleanup
)

REM Extract ngrok
echo Extracting ngrok...
powershell -Command "Expand-Archive -Path 'ngrok.zip' -DestinationPath '.' -Force"
if not exist "ngrok.exe" (
    echo ❌ Failed to extract ngrok.exe
    goto :cleanup
)

REM Try to install to a directory in PATH
set "install_success=false"

REM Try Program Files
if exist "C:\Program Files" (
    if not exist "C:\Program Files\ngrok" mkdir "C:\Program Files\ngrok"
    copy "ngrok.exe" "C:\Program Files\ngrok\" >nul 2>&1
    if %errorlevel% equ 0 (
        echo ✅ ngrok installed to: C:\Program Files\ngrok\ngrok.exe
        echo Please add C:\Program Files\ngrok to your PATH environment variable
        set "install_success=true"
        goto :cleanup
    )
)

REM Try LocalAppData
if exist "%LOCALAPPDATA%" (
    if not exist "%LOCALAPPDATA%\ngrok" mkdir "%LOCALAPPDATA%\ngrok"
    copy "ngrok.exe" "%LOCALAPPDATA%\ngrok\" >nul 2>&1
    if %errorlevel% equ 0 (
        echo ✅ ngrok installed to: %LOCALAPPDATA%\ngrok\ngrok.exe
        echo Please add %LOCALAPPDATA%\ngrok to your PATH environment variable
        set "install_success=true"
        goto :cleanup
    )
)

REM Try user's home directory
if exist "%USERPROFILE%" (
    if not exist "%USERPROFILE%\ngrok" mkdir "%USERPROFILE%\ngrok"
    copy "ngrok.exe" "%USERPROFILE%\ngrok\" >nul 2>&1
    if %errorlevel% equ 0 (
        echo ✅ ngrok installed to: %USERPROFILE%\ngrok\ngrok.exe
        echo Please add %USERPROFILE%\ngrok to your PATH environment variable
        set "install_success=true"
        goto :cleanup
    )
)

REM If all else fails, leave in current directory
echo ⚠️  Could not install to standard locations
echo ngrok.exe is available in: %temp_dir%
echo Please manually add this directory to your PATH

:cleanup
REM Clean up temporary files
if exist "ngrok.zip" del "ngrok.zip"
if exist "ngrok.exe" del "ngrok.exe"
cd /d "%~dp0"

if "%install_success%"=="true" (
    echo.
    echo 🎯 ngrok installation completed!
    echo.
    echo To add ngrok to PATH permanently:
    echo 1. Open System Properties (Win + Pause/Break)
    echo 2. Click "Environment Variables"
    echo 3. Edit "Path" variable
    echo 4. Add the ngrok directory path
    echo 5. Click OK and restart your terminal
) else (
    echo.
    echo ⚠️  ngrok downloaded but not added to PATH
    echo Please manually add the ngrok directory to your PATH
)

:check_ssh
REM Check if SSH is available (for localhost.run tunnel)
where ssh >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ SSH is available
) else (
    echo ❌ SSH is not available
    echo Note: SSH is required for localhost.run tunnel
)

REM Check if Zphisher is available
if exist "backend\zphisher\zphisher.sh" (
    echo ✅ Zphisher script found
) else (
    echo ❌ Zphisher script not found
)

echo.
echo 🎯 Zphisher dependency check complete!
echo.
echo To use ngrok with authentication (recommended):
echo 1. Sign up at https://ngrok.com
echo 2. Get your auth token from the dashboard
echo 3. Run: ngrok authtoken YOUR_TOKEN
echo.
echo To start Zphisher with ngrok:
echo 1. Start the backend: cd backend ^&^& python app.py
echo 2. Start the frontend: cd frontend ^&^& npm run dev
echo 3. Open the Zphisher tool in the web interface
echo.
pause 