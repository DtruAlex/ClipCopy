# Multi-Room Clipboard Sync - Usage Guide

## Quick Start

### 1. Start the Hub (Terminal 1)
```bash
python ClipHub.py
```

### 2. Start the Agent (Terminal 2)
```bash
python tui_agent.py
```

## TUI Layout (Compact for small terminals)

The interface is now optimized for terminals as small as 80x24:

```
┌──────────────────────────────────────────────────────────┐
│ 🔄 Multi-Room Clipboard 🟢 0 rooms                      │ ← Header (3 lines)
├──────────────────────┬───────────────────────────────────┤
│ 🚪 Rooms             │ 📊 Activity                       │
│ No rooms             │ Waiting for activity...           │
│                      │                                   │
│                      │                                   │
│                      ├───────────────────────────────────┤
│                      │ 📋 Clipboard                      │
│                      │ Copy to start syncing             │
│                      │                                   │
├──────────────────────┴───────────────────────────────────┤
│ 💡 Command                                               │ ← Input (4 lines)
│ > [cursor here]                                          │
│ /join <room> <key>  /leave <room>  /list /quit          │
└──────────────────────────────────────────────────────────┘
```

**Layout Features:**
- **Left side (26 cols)**: Rooms panel - shows all joined rooms
- **Right side**: Split vertically:
  - **Top half**: Activity log - shows sync events
  - **Bottom half**: Clipboard preview - shows current content

## Commands

Type directly in the TUI (no need to press anything first):

- `/join work secretkey123` - Join a room
- `/leave work` - Leave a room
- `/list` - Show all rooms you're in
- `/quit` or Ctrl+C - Exit

## How it works

1. **Copy something** (Ctrl+C) on any device
2. It **automatically syncs** to all other devices in the same room
3. **Paste** (Ctrl+V) on another device - it just works!

## Multi-Room Example

```
# Device 1
/join work secret123
/join home password456

# Now copy something - it goes to BOTH rooms!
# Other devices in "work" or "home" will receive it
```

## Tips

- **Minimum terminal size**: 80 columns x 24 rows
- **Polling interval**: 0.1s (clipboard detected almost instantly)
- **Refresh rate**: 10 FPS (smooth and responsive)
- **Text appears as you type** in the command input area
- **Events scroll** in the Activity panel (shows last 15)

## Troubleshooting

**TUI extends beyond screen?**
- Resize your terminal to at least 80x24
- Use fullscreen mode
- The layout is now optimized for small screens

**Can't see what I'm typing?**
- Look at the "> " prompt in the Command panel at the bottom
- Your text appears with a blinking cursor

**Clipboard not syncing?**
- Make sure you're in the same room on both devices
- Check that both devices show 🟢 (connected) in the header
- Room names and keys must match exactly
