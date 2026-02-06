#!/usr/bin/env python3
"""
Multi-Room Clipboard Sync with Rich TUI.
Automatic clipboard synchronization across devices with URL security checking.

Usage:
    python tui_agent.py [--host HOST] [--port PORT]

Commands (in TUI):
    /join <room> <key>  - Join a room with encryption key
    /leave <room>       - Leave a room
    /list               - List all rooms
    /refresh            - Reconnect to hub (refresh connection)
    /quit               - Exit application

Security Features:
    - Automatic URL threat detection on incoming clipboard
    - Typosquatting detection (homoglyphs, Cyrillic lookalikes)
    - Domain age verification
    - Blocks dangerous URLs (threat score >= 80)
"""
import argparse
import sys
import time
import threading
from datetime import datetime
from typing import Optional

# Platform-specific input handling
if sys.platform == 'win32':
    import msvcrt
    def get_key():
        """Read a single key from stdin (Windows)"""
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            # Handle special keys
            if ch in (b'\x00', b'\xe0'):
                msvcrt.getch() # Skip second part
                return None
            return ch.decode('utf-8', errors='ignore')
        time.sleep(0.01)
        return None
else:
    import tty
    import termios
    import select

    def get_key():
        """Read a single key from stdin (Unix) without breaking output formatting"""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            # Create a copy of the settings
            new_settings = termios.tcgetattr(fd)
            # Disable canonical mode (line buffering) and echo
            # lflag (local modes) is index 3
            new_settings[3] = new_settings[3] & ~termios.ICANON & ~termios.ECHO

            # Apply new settings immediately
            # TCSADRAIN waits for output to be transmitted; TCSANOW changes immediately
            termios.tcsetattr(fd, termios.TCSANOW, new_settings)

            # Check if data is available to read
            dr, dw, de = select.select([sys.stdin], [], [], 0.01)
            if dr:
                ch = sys.stdin.read(1)
                return ch
            return None

        finally:
            # Restore original settings
            termios.tcsetattr(fd, termios.TCSANOW, old_settings)

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: 'rich' library not installed.")
    print("Install with: pip install rich")
    sys.exit(1)

from MultiRoomAgent import MultiRoomAgent
from clipboard_handler import ClipboardData


class ClipboardTUI:
    """Terminal UI for multi-room clipboard sync"""

    def __init__(self, hub_host: str = '127.0.0.1', hub_port: int = 9999):
        self.console = Console()
        # Fast polling for real-time feel with URL verification enabled
        self.agent = MultiRoomAgent(hub_host, hub_port, poll_interval=0.1, enable_url_verification=True)

        # Event log
        self.events: list = []
        self.max_events = 50

        # Current clipboard preview
        self.current_clipboard: Optional[ClipboardData] = None
        self.current_clipboard_source: str = ""

        # Status
        self.running = True
        self.status = "starting"

        # Input buffer
        self.input_buffer = ""
        self.cursor_visible = True
        self.last_cursor_toggle = time.time()

        # URL Threat Alert
        self.current_threat_alert = None  # Stores current threat info for popup
        self.threat_alert_time = 0  # When the alert was shown

        # Setup agent callbacks
        self.agent.on_clipboard_send = self._on_clipboard_send
        self.agent.on_clipboard_receive = self._on_clipboard_receive
        self.agent.on_room_change = self._on_room_change
        self.agent.on_error = self._on_error
        self.agent.on_status_change = self._on_status_change
        self.agent.on_url_threat = self._on_url_threat

    def _add_event(self, message: str, style: str = ""):
        """Add event to the log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if style:
            self.events.append(f"[dim]{timestamp}[/dim] [{style}]{message}[/{style}]")
        else:
            self.events.append(f"[dim]{timestamp}[/dim] {message}")

        # Trim old events
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

    def _on_clipboard_send(self, room_name: str, clipboard_data: ClipboardData):
        """Callback when sending clipboard to a room"""
        content_type = clipboard_data.get_primary_type()
        size = clipboard_data.get_size()
        emoji = {"text": "📝", "image": "🖼️", "html": "🌐", "rtf": "📄", "files": "📎"}.get(content_type, "📋")
        self._add_event(f"{emoji} Sent to [cyan]{room_name}[/cyan]: {content_type} ({size:,} bytes)")
        self.current_clipboard = clipboard_data
        self.current_clipboard_source = "local"

    def _on_clipboard_receive(self, room_name: str, clipboard_data: ClipboardData):
        """Callback when receiving clipboard from a room"""
        content_type = clipboard_data.get_primary_type()
        size = clipboard_data.get_size()
        emoji = {"text": "📝", "image": "🖼️", "html": "🌐", "rtf": "📄", "files": "📎"}.get(content_type, "📋")
        self._add_event(f"{emoji} Received from [magenta]{room_name}[/magenta]: {content_type} ({size:,} bytes)", "green")
        self.current_clipboard = clipboard_data
        self.current_clipboard_source = room_name

    def _on_room_change(self, action: str, room_name: str):
        """Callback on room join/leave"""
        if action == 'join':
            self._add_event(f"➕ Joined room: [cyan]{room_name}[/cyan]", "green")
        else:
            self._add_event(f"➖ Left room: [yellow]{room_name}[/yellow]")

    def _on_error(self, message: str):
        """Callback on error"""
        self._add_event(f"❌ {message}", "red")

    def _on_status_change(self, status: str):
        """Callback on connection status change"""
        self.status = status
        if status == "connected":
            self._add_event("✅ Connected to hub", "green")
        elif status == "disconnected":
            self._add_event("🔌 Disconnected from hub", "yellow")

    def _on_url_threat(self, source: str, verification: dict):
        """Callback when URL threat is detected"""
        threat_score = verification.get('max_threat_score', 0)

        if threat_score >= 80:
            emoji = "🔴"
            style = "red bold"
            level = "DANGEROUS"
        elif threat_score >= 50:
            emoji = "🟠"
            style = "yellow bold"
            level = "SUSPICIOUS"
        else:
            emoji = "🟡"
            style = "yellow"
            level = "QUESTIONABLE"

        # Log the threat
        self._add_event(
            f"{emoji} URL THREAT from {source}: {level} (score: {threat_score}/100)",
            style
        )

        # Log details about each URL
        for url_info in verification.get('urls', []):
            if not url_info.get('safe', True):
                domain = url_info.get('domain', 'unknown')
                threats = url_info.get('threats', [])
                self._add_event(f"  ⚠️  {domain}: {', '.join(threats)}", "yellow")

        # Store threat for popup display
        self.current_threat_alert = {
            'source': source,
            'level': level,
            'emoji': emoji,
            'score': threat_score,
            'verification': verification,
            'time': time.time()
        }
        self.threat_alert_time = time.time()

    def _create_header(self) -> Panel:
        """Create the header panel"""
        # Status indicator
        if self.status == "connected":
            status_icon = "🟢"
            status_style = "green"
        elif self.status == "disconnected":
            status_icon = "🔴"
            status_style = "red"
        else:
            status_icon = "🟡"
            status_style = "yellow"

        content = Text()
        content.append("🔄 Multi-Room Clipboard ", style="bold white")
        content.append(status_icon, style=status_style)
        content.append(f" {self.agent.get_room_count()} rooms", style="cyan")

        return Panel(content, style="blue", border_style="bright_blue", padding=(0, 1))

    def _create_rooms_panel(self) -> Panel:
        """Create the rooms status panel"""
        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE, padding=(0, 1))
        table.add_column("Room", style="cyan", width=15, no_wrap=True)
        table.add_column("Syncs", justify="right", style="green", width=6)
        table.add_column("Activity", style="yellow", width=10)

        rooms_info = self.agent.get_rooms_info()

        if not rooms_info:
            table.add_row("[dim]No rooms[/dim]", "-", "-")
        else:
            for room_name, info in sorted(rooms_info.items()):
                # Calculate time ago
                if info['last_activity'] > 0:
                    time_ago = time.time() - info['last_activity']
                    if time_ago < 60:
                        activity = f"{int(time_ago)}s ago"
                    elif time_ago < 3600:
                        activity = f"{int(time_ago/60)}m ago"
                    else:
                        activity = f"{int(time_ago/3600)}h ago"
                else:
                    activity = "waiting"

                table.add_row(
                    f"🟢 {room_name[:12]}",
                    str(info['sync_count']),
                    activity
                )

        return Panel(table, title="🚪 Rooms", border_style="magenta", padding=(0, 0))

    def _create_clipboard_panel(self) -> Panel:
        """Create the clipboard preview panel"""
        text = Text()

        if self.current_clipboard and not self.current_clipboard.is_empty():
            content_type = self.current_clipboard.get_primary_type()
            size = self.current_clipboard.get_size()

            # Compact info
            text.append(f"{content_type.upper()} ", style="cyan bold")
            text.append(f"({size:,}b)", style="yellow")

            if self.current_clipboard_source and self.current_clipboard_source != "local":
                text.append(f" from {self.current_clipboard_source}", style="magenta")

            text.append("\n")

            # Show full content instead of truncated preview
            # Use raw text if available to show "everything"
            if hasattr(self.current_clipboard, 'text') and self.current_clipboard.text:
                full_text = self.current_clipboard.text
                # Safety capability limit for TUI performance (5000 chars approx 1-2 pages)
                if len(full_text) > 5000:
                    text.append(full_text[:5000] + "\n... [Content truncated for display performance]", style="white")
                else:
                    text.append(full_text, style="white")
            else:
                # Fallback for binary/image data
                preview = self.current_clipboard.get_preview(100)
                text.append(preview, style="white")
        else:
            text.append("Copy to start syncing", style="dim italic")

        return Panel(text, title="📋 Clipboard", border_style="green", padding=(0, 1))

    def _create_events_panel(self) -> Panel:
        """Create the events log panel"""
        if not self.events:
            content = Text("Waiting for activity...", style="dim")
        else:
            # Dynamic height calculation to allow scrolling/filling the view
            # Layout structure:
            # Header(3) + Footer(4) = 7 lines fixed
            # Body takes remainder. Right side split 50/50 between Activity and Clipboard.

            term_height = self.console.height
            body_height = term_height - 7
            # Activity gets half of body. Subtract 2 for panel borders.
            available_lines = max(5, (body_height // 2) - 2)

            # Show strictly the number of events that fit
            recent_events = self.events[-available_lines:]
            content = Text.from_markup("\n".join(recent_events))

        return Panel(content, title="📊 Activity", border_style="yellow", padding=(0, 1))

    def _create_help_panel(self) -> Panel:
        """Create the help/commands/input panel"""
        # Toggle cursor blink
        if time.time() - self.last_cursor_toggle > 0.5:
            self.cursor_visible = not self.cursor_visible
            self.last_cursor_toggle = time.time()

        cursor = "█" if self.cursor_visible else " "

        text = Text()

        # Display input area
        text.append("> ", style="bold green")
        text.append(self.input_buffer, style="bold white")
        text.append(cursor, style="bright_green")
        text.append("\n", style="default")

        # Compact command reference
        text.append("/join <room> <key>  /leave <room>  /list  /refresh  /quit", style="dim cyan")

        return Panel(text, title="💡 Command", border_style="blue", padding=(0, 1))

    def _create_threat_alert_panel(self) -> Optional[Panel]:
        """Create a prominent threat alert popup panel"""
        if not self.current_threat_alert:
            return None

        # Auto-dismiss after 10 seconds
        if time.time() - self.threat_alert_time > 10:
            self.current_threat_alert = None
            return None

        alert = self.current_threat_alert
        text = Text()

        # Header with emoji and level
        text.append(f"\n{alert['emoji']} ", style="bold")
        text.append(f"URL THREAT DETECTED: {alert['level']}\n", style="bold red")
        text.append("="*60 + "\n", style="red")

        # Score
        text.append(f"Threat Score: {alert['score']}/100", style="bold yellow")
        text.append(f" from {alert['source']}\n\n", style="cyan")

        # Details about each threatening URL
        for url_info in alert['verification'].get('urls', []):
            if not url_info.get('safe', True):
                domain = url_info.get('domain', 'unknown')
                url = url_info.get('url', domain)

                text.append("🔗 ", style="red")
                text.append(f"{url}\n", style="bold white")
                text.append(f"   Domain: {domain}\n", style="yellow")

                threats = url_info.get('threats', [])
                if threats:
                    text.append("   Threats:\n", style="red")
                    for threat in threats:
                        text.append(f"   • {threat}\n", style="yellow")

        text.append("\n" + "="*60 + "\n", style="red")

        # Action taken
        if alert['score'] >= 80:
            text.append("🛑 CLIPBOARD BLOCKED", style="bold red blink")
            text.append(" - Content was NOT copied\n", style="red")
        else:
            text.append("⚠️  WARNING", style="bold yellow")
            text.append(" - Be careful with this content\n", style="yellow")

        text.append("\nPress any key to dismiss...", style="dim")

        # Create panel with attention-grabbing border
        border_style = "red bold" if alert['score'] >= 80 else "yellow bold"
        return Panel(
            text,
            title=f"⚠️  SECURITY ALERT ⚠️",
            border_style=border_style,
            padding=(1, 2),
            style="on red" if alert['score'] >= 80 else "on yellow"
        )

    def _create_layout(self) -> Layout:
        """Create the full TUI layout"""
        # Check if we should show threat alert
        threat_panel = self._create_threat_alert_panel()

        if threat_panel:
            # Show threat alert as main content (overlay everything)
            layout = Layout()
            layout.update(threat_panel)
            return layout

        # Normal layout
        layout = Layout()

        # Main structure - more compact
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=4),
        )

        # Body: left sidebar (rooms) + right content (activity + clipboard)
        layout["body"].split_row(
            Layout(name="rooms", size=26),
            Layout(name="right", ratio=1),
        )

        # Right side: split activity and clipboard vertically
        layout["right"].split_column(
            Layout(name="activity", ratio=1),
            Layout(name="clipboard", ratio=1),
        )

        # Update all panels
        layout["header"].update(self._create_header())
        layout["rooms"].update(self._create_rooms_panel())
        layout["activity"].update(self._create_events_panel())
        layout["clipboard"].update(self._create_clipboard_panel())
        layout["footer"].update(self._create_help_panel())

        return layout

    def _process_command(self, cmd: str):
        """Process a text command"""
        parts = cmd.strip().split(maxsplit=2)
        if not parts:
            return

        command = parts[0].lower()

        if command == '/join' and len(parts) >= 3:
            room_name = parts[1]
            key = parts[2]
            self.agent.join_room(room_name, key)

        elif command == '/leave' and len(parts) >= 2:
            room_name = parts[1]
            self.agent.leave_room(room_name)

        elif command == '/list':
            rooms = self.agent.get_rooms_info()
            if rooms:
                room_list = ", ".join(rooms.keys())
                self._add_event(f"📋 Active rooms: {room_list}")
            else:
                self._add_event("📋 No rooms joined yet")

        elif command == '/refresh':
            # Reconnect to hub
            self._add_event("🔄 Refreshing connection to hub...")
            try:
                # Stop current agent
                self.agent.stop()
                time.sleep(0.5)  # Give it time to clean up

                # Restart agent
                if self.agent.start():
                    self._add_event("✅ Reconnected to hub successfully", "green")
                else:
                    self._add_event("❌ Failed to reconnect to hub", "red")
            except Exception as e:
                self._add_event(f"❌ Error reconnecting: {e}", "red")

        elif command == '/quit' or command == '/exit' or command == '/q':
            self.running = False

        elif command.startswith('/'):
            self._add_event(f"⚠️ Unknown command: {command}", "yellow")
        else:
             self._add_event(f"⚠️ Commands must start with /", "yellow")

    def _command_loop(self):
        """Background thread: Handle raw user input"""
        while self.running:
            try:
                char = get_key()

                if char is None:
                    continue

                # If threat alert is showing, any key dismisses it
                if self.current_threat_alert:
                    self.current_threat_alert = None
                    continue

                # Check for Ctrl+C -> Exit
                if char == '\x03':
                    self.running = False
                    break

                # Check for Enter -> Process command
                if char == '\r' or char == '\n':
                    if self.input_buffer:
                        self._process_command(self.input_buffer)
                        self.input_buffer = ""
                    continue

                # Check for Backspace
                if char == '\x7f' or char == '\x08':
                    self.input_buffer = self.input_buffer[:-1]
                    continue

                # Check for printable characters
                if len(char) == 1 and char.isprintable():
                    self.input_buffer += char

            except Exception:
                # If reading fails, just sleep a bit and try again
                time.sleep(0.1)

    def run(self):
        """Run the TUI application"""
        try:
            # Show startup message
            self._add_event("🚀 Starting clipboard agent...")

            # Start agent
            if not self.agent.start():
                self._add_event("❌ Failed to connect to hub", "red")
                self._add_event(f"   Make sure ClipHub is running on {self.agent.hub_host}:{self.agent.hub_port}", "dim")
                self.status = "disconnected"

            self._add_event("💡 Use /join <room> <key> to join a room")

            # Start command input thread
            cmd_thread = threading.Thread(target=self._command_loop, daemon=True, name="CommandInput")
            cmd_thread.start()

            # Main TUI render loop - faster refresh for input responsiveness
            with Live(
                self._create_layout(),
                console=self.console,
                refresh_per_second=10,
                screen=True,
                transient=False
            ) as live:
                while self.running:
                    live.update(self._create_layout())
                    time.sleep(0.05)

        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
        finally:
            self.agent.stop()
            self.console.print("\n[yellow]👋 Clipboard sync stopped. Goodbye![/yellow]\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Multi-Room Clipboard Sync with TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tui_agent.py                    # Connect to localhost:9999
  python tui_agent.py --host 192.168.1.5 # Connect to remote hub
  python tui_agent.py --port 8888        # Use custom port

In the TUI:
  /join work secretkey123    # Join 'work' room with key
  /join personal mypass456   # Join another room
  /leave work                # Leave a room
  /quit                      # Exit
        """
    )
    parser.add_argument('--host', default='127.0.0.1', help='Hub server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=9999, help='Hub server port (default: 9999)')

    args = parser.parse_args()

    console = Console()

    try:
        console.print("[bold cyan]🔄 Multi-Room Clipboard Sync[/bold cyan]")
        console.print(f"[dim]Connecting to {args.host}:{args.port}...[/dim]\n")

        tui = ClipboardTUI(args.host, args.port)
        tui.run()

        return 0

    except Exception as e:
        console.print(f"[bold red]❌ Fatal error:[/bold red] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
