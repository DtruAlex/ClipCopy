# Multi-Room Clipboard Sync

🔄 **Automatic clipboard synchronization across devices** with rich format support (text, images, HTML, RTF).

Copy on one device (Ctrl+C), automatically available on all other devices in the same room. No manual sending - just seamless clipboard sharing.

## Features

- 🔄 **Automatic sync**: Copy on one device, instantly available on all others
- 🚪 **Multi-room**: Join multiple rooms simultaneously 
- 🔒 **Encrypted**: Each room has its own encryption key
- 📋 **Rich clipboard**: Supports text, images, HTML, RTF (not just plain text)
- 🎨 **Beautiful TUI**: Real-time visualization of sync activity
- 🖥️ **Cross-platform**: Works on Windows, macOS, and Linux

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Hub (on one machine or server)

```bash
python ClipHub.py
```

Output:
```
[*] Multi-Room Clipboard Hub initialized on 0.0.0.0:9999
[*] Waiting for clients...
```

### 3. Start the Agent (on each device)

```bash
python tui_agent.py
```

For remote hub:
```bash
python tui_agent.py --host 192.168.1.100 --port 9999
```

### 4. Join Rooms (in TUI)

```
/join work secretkey123
/join personal mypassword456
```

### 5. Start Copying!

Just use Ctrl+C and Ctrl+V as normal. Clipboard automatically syncs to all devices in your rooms.

## TUI Commands

| Command | Description |
|---------|-------------|
| `/join <room> <key>` | Join a room with encryption key |
| `/leave <room>` | Leave a room |
| `/list` | List active rooms |
| `/quit` | Exit application |

## Architecture

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Device A   │         │   ClipHub    │         │   Device B   │
│              │◄───────►│   (Server)   │◄───────►│              │
│ Rooms:       │   TCP   │              │   TCP   │ Rooms:       │
│  - work      │         │ Multi-Room   │         │  - work      │
│  - personal  │         │   Routing    │         │  - home      │
└──────────────┘         └──────────────┘         └──────────────┘
         │                                                │
         │           Clipboard syncs automatically        │
         └────────────────────────────────────────────────┘
```

## Platform Support

| Platform | Text | Images | HTML | RTF | Files |
|----------|------|--------|------|-----|-------|
| Windows  | ✅   | ✅     | ✅   | ✅  | ⚠️*   |
| macOS    | ✅   | ✅     | ⚠️   | ❌  | ⚠️*   |
| Linux    | ✅   | ✅     | ❌   | ❌  | ⚠️*   |

*Files sync paths only, not content

## File Structure

```
DS_ClipCopy/
├── ClipHub.py           # Hub server (run on one machine)
├── tui_agent.py         # TUI client (run on each device)
├── MultiRoomAgent.py    # Multi-room agent logic
├── ClipProtocol.py      # Binary protocol definition
├── clipboard_handler.py # Rich clipboard support
├── utils.py             # Encryption utilities
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## How It Works

1. **Hub Server**: Central relay that routes clipboard data between clients
2. **Agent**: Runs on each device, monitors clipboard for changes
3. **Rooms**: Clients join "rooms" - only devices in the same room share clipboards
4. **Encryption**: Each room has its own key - data is encrypted before transmission
5. **Rich Formats**: Clipboard is captured with all formats (text, images, HTML, etc.)

### Sync Flow

1. You copy text/image on Device A (Ctrl+C)
2. Agent detects clipboard change (polls every 500ms)
3. Agent encrypts data with room key
4. Agent sends to Hub with room name
5. Hub broadcasts to all other clients in that room
6. Device B's agent receives, decrypts, verifies authentication, and sets local clipboard
7. You can now paste on Device B (Ctrl+V)

## Security Features

✅ **Production-Grade Security:**

- **AES-256-GCM Encryption**: Industry-standard authenticated encryption (AEAD)
- **Authentication Tags**: 16-byte tags prevent tampering - any modification causes immediate failure
- **Key Derivation**: SHA-256 hashing of room passwords to 256-bit keys
- **Random Nonces**: 96-bit unique nonces per message prevent replay attacks
- **Pure Binary Protocol**: Efficient struct.pack serialization (no JSON overhead)
- **Per-Room Keys**: Independent encryption for each room

⚠️ **Security Considerations:**

- Only join rooms you trust - clipboard can contain sensitive data
- Use strong room passwords (≥12 characters, mixed case, numbers, symbols)
- Hub sees encrypted traffic but cannot decrypt without room keys
- Hub should be on a trusted network (or use VPN)

## Troubleshooting

### "Connection failed"
- Make sure ClipHub.py is running
- Check firewall allows port 9999
- Verify --host and --port match the hub

### "Decrypt failed" errors
- Verify all clients in room use the same password
- Authentication failure means data was tampered or wrong key

### "pyperclip not found"
```bash
pip install pyperclip
```

### "No image support"
```bash
pip install Pillow
```

### "No rich clipboard on Windows"
```bash
pip install pywin32
```

## License

MIT License - feel free to use and modify!
