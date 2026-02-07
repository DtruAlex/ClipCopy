#!/bin/bash
# =============================================================================
# Multi-Room Clipboard Sync - Installation Script (macOS / Linux)
# Installs dependencies, sets up the TUI, and configures autostart
# =============================================================================

set -e

echo "================================================"
echo "  Multi-Room Clipboard Sync - Installation"
echo "================================================"
echo ""

# Check Python
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[X] Python3 not found. Please install Python 3.11 or higher."
    echo "    macOS: brew install python3"
    echo "    Ubuntu/Debian: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi
echo "[+] Python found: $(python3 --version)"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ -d ".venv" ]; then
    echo "[!] Virtual environment already exists, skipping..."
else
    python3 -m venv .venv
    echo "[+] Virtual environment created"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip --quiet

# Install dependencies
echo ""
echo "Installing dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet
else
    echo "requirements.txt not found, installing packages manually..."
    pip install cryptography pyperclip pillow rich requests python-whois --quiet
fi
echo "[+] All dependencies installed"

# Make start script executable
echo ""
echo "Setting up startup scripts..."
chmod +x start_agent.sh 2>/dev/null || true
echo "[+] start_agent.sh is executable"

# Platform-specific autostart configuration
echo ""
echo "Configuring autostart..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - Create LaunchAgent plist
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/com.dsclip.agent.plist"

    mkdir -p "$PLIST_DIR"

    cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dsclip.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$SCRIPT_DIR/start_agent.sh</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>WorkingDirectory</key>
    <string>$SCRIPT_DIR</string>
    <key>StandardOutPath</key>
    <string>$SCRIPT_DIR/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$SCRIPT_DIR/agent.log</string>
</dict>
</plist>
EOF

    echo "[+] LaunchAgent plist created: $PLIST_FILE"
    echo "    To enable autostart: launchctl load $PLIST_FILE"
    echo "    To disable autostart: launchctl unload $PLIST_FILE"

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux - Create systemd user service or desktop autostart
    AUTOSTART_DIR="$HOME/.config/autostart"
    DESKTOP_FILE="$AUTOSTART_DIR/dsclip-agent.desktop"

    mkdir -p "$AUTOSTART_DIR"

    cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Type=Application
Name=DS ClipCopy Agent
Comment=Multi-Room Clipboard Sync
Exec=$SCRIPT_DIR/start_agent.sh
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=false
Terminal=true
EOF

    echo "[+] Desktop autostart file created: $DESKTOP_FILE"
    echo "    To enable: Set X-GNOME-Autostart-enabled=true in the file"
    echo "    Or use your desktop environment's Startup Applications settings"
fi

# Final instructions
echo ""
echo "================================================"
echo "  Installation Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Start the ClipHub server (on one machine):"
echo "   python ClipHub.py"
echo ""
echo "2. Run the clipboard sync client:"
echo "   ./start_agent.sh"
echo ""
echo "3. In the TUI, type this command to join a room:"
echo "   /join personal YOUR_PASSWORD"
echo ""
echo "Security Features:"
echo "  [+] End-to-end encryption (AES-256-GCM)"
echo "  [+] URL threat detection enabled"
echo "  [+] Automatic typosquatting detection"
echo ""
echo "Note: Make sure the ClipHub server is running before starting clients!"
echo ""
