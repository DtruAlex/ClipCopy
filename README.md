# ClipCopy - Multi-Room Clipboard Sync

Secure, real-time clipboard synchronization across multiple devices. Copy on one computer, paste on another.

---

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Component Guide: Hub Server](#component-guide-hub-server)
4. [Component Guide: Client Agent](#component-guide-client-agent)
5. [Component Guide: URL Security](#component-guide-url-security)
6. [Troubleshooting](#troubleshooting)

---

## Overview

ClipCopy consists of three main components:

| Component | Purpose |
|-----------|---------|
| **Hub (Server)** | Central relay that routes encrypted clipboard data between clients. Does not decrypt data. |
| **Agent (Client)** | Runs on each device. Monitors clipboard, encrypts changes, sends/receives from Hub. |
| **URL Security** | Scans clipboard content for malicious links before syncing. |

### Supported Content Types

| Platform | Text | Images | HTML | RTF |
|----------|------|--------|------|-----|
| Windows  | ✅   | ✅     | ✅   | ✅  |
| macOS    | ✅   | ✅     | ⚠️   | ❌  |
| Linux    | ✅   | ✅     | ❌   | ❌  |

---

## Installation

### Prerequisites
- Python 3.11 or higher
- pip (Python package manager)

### Steps

**macOS / Linux:**
```bash
./install.sh
```

**Windows:**
```cmd
install.bat
```

This creates a virtual environment (`.venv`) and installs all dependencies from `requirements.txt`.

---

## Component Guide: Hub Server

The Hub is a lightweight server that routes encrypted clipboard data between connected clients. It never decrypts the data—it only verifies that clients know the room password using a challenge-response protocol.

### Option 1: Run Locally (Python)

```bash
# Activate virtual environment first
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows

# Start the hub on default port 9999
python ClipHub.py

# Or specify host and port
python ClipHub.py 0.0.0.0 9999
```

Expected output:
```
[*] Multi-Room Clipboard Hub initialized on 0.0.0.0:9999
[*] Using AES-256-GCM encryption (clients encrypt/decrypt)
[*] Challenge-response authentication enabled
[*] Binary protocol (no JSON overhead)
[*] Waiting for clients...
```

### Option 2: Run with Docker (Recommended for Servers)

**Build the image:**
```bash
docker build -t cliphub .
```

**Run the container:**
```bash
docker run -d -p 9999:9999 --name cliphub --restart unless-stopped cliphub
```

**View logs:**
```bash
docker logs -f cliphub
```

**Stop the container:**
```bash
docker stop cliphub
docker rm cliphub
```

### Option 3: Docker Compose

```bash
docker-compose up -d
```

### Environment Variables (Docker/Cloud)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9999` | Port to listen on (used by Azure, Heroku, etc.) |
| `HOST` | `0.0.0.0` | Bind address |

### Firewall Configuration

Ensure port `9999` (or your chosen port) is open for TCP traffic:
- **Linux:** `sudo ufw allow 9999/tcp`
- **Windows:** Add inbound rule in Windows Firewall
- **Cloud:** Configure security group / network rules

---

## Component Guide: Client Agent

The Agent runs on each device you want to sync. It monitors your clipboard for changes, encrypts the content, and sends it to the Hub. It also receives updates from other devices and applies them to your local clipboard.

### Starting the Agent

**macOS / Linux:**
```bash
./start_agent.sh
```

**Windows:**
```cmd
start_clipboard_sync.bat
```

**Or manually:**
```bash
source .venv/bin/activate
python tui_agent.py
```

### Connecting to a Remote Hub

```bash
python tui_agent.py --host 192.168.1.100 --port 9999
```

Or for a cloud-hosted hub:
```bash
python tui_agent.py --host your-server.example.com --port 9999
```

### TUI Interface

The agent displays a terminal interface with:
- **Rooms Panel:** Shows joined rooms and sync statistics
- **Activity Log:** History of sent/received clipboard items
- **Clipboard Preview:** Current clipboard content
- **Command Input:** Type commands here

### Commands

| Command | Usage | Description |
|---------|-------|-------------|
| `/join` | `/join <room> <password>` | Join a room. Creates the room if it doesn't exist. |
| `/leave` | `/leave <room>` | Leave a room. |
| `/list` | `/list` | Show all joined rooms. |
| `/refresh` | `/refresh` | Reconnect to the hub. |
| `/quit` | `/quit` | Exit the application. |

### Example Session

```
> /join work MySecretPassword123
✅ Joined room: work

> /join personal AnotherPassword456
✅ Joined room: personal

> /list
📋 Active rooms: work, personal

> /leave work
➖ Left room: work

> /quit
👋 Clipboard sync stopped. Goodbye!
```

### How Syncing Works

1. You copy something (`Ctrl+C` / `Cmd+C`) on Device A.
2. The Agent detects the clipboard change.
3. Content is encrypted with the room's password.
4. Encrypted data is sent to the Hub.
5. Hub broadcasts to all other clients in the same room.
6. Device B's Agent receives, decrypts, and sets local clipboard.
7. You paste (`Ctrl+V` / `Cmd+V`) on Device B.

---

## Component Guide: URL Security

ClipCopy includes built-in protection against malicious URLs in clipboard content. This feature is enabled by default.

### What It Detects

| Threat Type | Description | Example |
|-------------|-------------|---------|
| **Typosquatting** | Domains that mimic legitimate sites | `amaz0n.com`, `paypa1.com` |
| **Homoglyph Attacks** | Using look-alike characters | `gοοgle.com` (Greek 'ο' instead of 'o') |
| **Suspicious TLDs** | Uncommon top-level domains often used in phishing | `.xyz`, `.top`, `.click` |
| **New Domains** | Recently registered domains (< 30 days) | Checked via WHOIS |

### Threat Levels

| Level | Score | Action |
|-------|-------|--------|
| 🟢 Safe | 0-29 | Content syncs normally |
| 🟡 Suspicious | 30-79 | Warning displayed, content still syncs |
| 🔴 Dangerous | 80-100 | **Content blocked**, not copied to clipboard |

### Security Alert Display

When a threat is detected, the TUI shows a prominent alert:
```
⚠️  SECURITY ALERT ⚠️
═══════════════════════════════════════════════════════════
🔴 URL THREAT DETECTED: DANGEROUS
Threat Score: 85/100 from room: work

🔗 https://paypa1-secure.com/login
   Domain: paypa1-secure.com
   Threats:
   • Typosquatting detected (similar to: paypal.com)
   • Suspicious TLD pattern

═══════════════════════════════════════════════════════════
🛑 CLIPBOARD BLOCKED - Content was NOT copied

Press any key to dismiss...
```

### Disabling URL Verification

If needed, you can disable URL scanning by modifying the agent initialization in `tui_agent.py`:
```python
self.agent = MultiRoomAgent(hub_host, hub_port, enable_url_verification=False)
```

**Note:** Disabling this feature is not recommended as it removes protection against phishing attacks.

---

## Troubleshooting

### Connection Issues

**"Connection failed" or "Connection refused"**
- Verify the Hub is running: `docker logs cliphub` or check terminal output
- Confirm the host and port are correct
- Check firewall rules on both client and server
- Test connectivity: `telnet <host> 9999` or `nc -zv <host> 9999`

**"Disconnected from hub"**
- Network interruption occurred
- Use `/refresh` command to reconnect
- Check if the Hub container/process is still running

### Authentication Issues

**"Failed to join room: Wrong password"**
- All clients in a room must use the exact same password
- Passwords are case-sensitive
- The first client to join a room sets the password

**"Decrypt failed"**
- Password mismatch between sender and receiver
- Possible data corruption (rare)

### Clipboard Issues

**"Clipboard not syncing"**
- Ensure both devices are in the same room
- Check the Activity panel for errors
- Verify the clipboard content is supported (text, image, etc.)

**"pyperclip not found"**
```bash
pip install pyperclip
```

**"No image support"**
```bash
pip install Pillow
```

**"No rich clipboard on Windows"**
```bash
pip install pywin32
```

---

## File Structure

```
ClipCopy/
├── ClipHub.py           # Hub server
├── tui_agent.py         # TUI client agent
├── MultiRoomAgent.py    # Agent logic
├── ClipProtocol.py      # Binary protocol
├── clipboard_handler.py # Clipboard access
├── url_verifier.py      # URL security scanner
├── typosquatting_detector.py  # Typosquatting detection
├── domain_verifier.py   # Domain age checking
├── utils.py             # Encryption utilities
├── start_agent.sh       # Linux/macOS launcher
├── start_agent.bat      # Windows launcher
├── install.sh           # Linux/macOS installer
├── install.bat          # Windows installer
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose configuration
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## Security Summary

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256-GCM (authenticated encryption) |
| Key Derivation | SHA-256 hash of room password |
| Authentication | HMAC challenge-response (password never transmitted) |
| Nonces | 96-bit random per message (prevents replay attacks) |
| Hub Privacy | Hub cannot decrypt content (zero-knowledge relay) |

---

## License

MIT License - Free to use and modify.
