"""
Multi-room clipboard synchronization client.

This client connects to a ClipHub server and automatically synchronizes
clipboard changes across multiple rooms. It monitors the local clipboard
and sends updates to all joined rooms, and receives updates from other
clients in those rooms.

Key Features:
- Automatic clipboard monitoring (detects Ctrl+C copy events)
- Support for multiple simultaneous rooms
- End-to-end encryption (per-room passwords)
- Rich clipboard support (text, images, HTML, etc.)
- Echo prevention (doesn't re-broadcast received content)
"""
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Callable, Set

from ClipProtocol import ClipProtocol, PacketType
from clipboard_handler import ClipboardHandler, ClipboardData
from utils import SecurityEngine

# Optional URL verification
try:
    from url_verifier import URLVerifier, format_verification_warning
    HAS_URL_VERIFICATION = True
except ImportError:
    HAS_URL_VERIFICATION = False


@dataclass
class RoomContext:
    """
    Information about a joined room.

    Attributes:
        name: Room name
        encryption_key: Password for encrypting/decrypting clipboard data
        last_hash: Hash of last clipboard from this room (prevents echo)
        sync_count: Number of successful syncs (for statistics)
        last_activity: Timestamp of last sync activity
    """
    name: str
    encryption_key: str
    last_hash: str = ""
    sync_count: int = 0
    last_activity: float = 0.0


class MultiRoomAgent:
    """
    Clipboard synchronization client.

    Architecture:
    - Main thread: Creates the agent and handles UI/commands
    - Monitor thread: Polls clipboard for changes and sends updates
    - Receiver thread: Receives updates from hub and applies to clipboard

    How it works:
    1. Connect to hub server
    2. Join one or more rooms with passwords
    3. Monitor thread detects local clipboard changes (Ctrl+C)
    4. Encrypts and sends to all joined rooms
    5. Receiver thread gets updates from other clients
    6. Decrypts and applies to local clipboard

    Echo prevention:
    - Tracks hashes of recently received clipboards
    - Won't re-send clipboard content that was just received
    - This prevents infinite loops of clipboard updates
    """

    def __init__(self, hub_host: str = '20.105.216.52', hub_port: int = 9999,
                 poll_interval: float = 0.1, enable_url_verification: bool = True):
        """
        Initialize the clipboard agent.

        Args:
            hub_host: IP address or hostname of the hub server
            hub_port: Port number the hub is listening on
            poll_interval: How often to check clipboard (seconds, default 0.1 = 100ms)
            enable_url_verification: Enable URL security scanning (default: True)
        """
        self.hub_host = hub_host
        self.hub_port = hub_port
        self.poll_interval = poll_interval

        # URL verification settings
        self.enable_url_verification = enable_url_verification and HAS_URL_VERIFICATION
        if enable_url_verification and not HAS_URL_VERIFICATION:
            print("[!] URL verification requested but modules not available")
            print("[!] Install with: pip install requests")
        elif self.enable_url_verification:
            print("[✓] URL security verification: ENABLED")
            print("[✓] Clipboard will be scanned for malicious URLs")

        # Network connection
        self.sock: Optional[socket.socket] = None

        # Room management: maps room name to room info
        self.rooms: Dict[str, RoomContext] = {}

        # Clipboard handler
        self.clipboard_handler = ClipboardHandler()

        # Control flags
        self.running = False
        self.connected = False

        # Thread safety
        self.lock = threading.RLock()

        # Echo prevention: Track recently received clipboard hashes
        self.received_hashes: Set[str] = set()
        self.max_received_hashes = 100  # Limit memory usage

        # Callbacks for UI integration (optional)
        self.on_clipboard_send: Optional[Callable[[str, ClipboardData], None]] = None
        self.on_clipboard_receive: Optional[Callable[[str, ClipboardData], None]] = None
        self.on_room_change: Optional[Callable[[str, str], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_status_change: Optional[Callable[[str], None]] = None
        self.on_url_threat: Optional[Callable[[str, Dict], None]] = None  # New callback for URL threats

    def connect(self) -> bool:
        """
        Establish connection to the hub server.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0)  # 10 second connection timeout
            self.sock.connect((self.hub_host, self.hub_port))
            self.sock.settimeout(None)  # Disable timeout for normal operations
            self.connected = True

            if self.on_status_change:
                self.on_status_change("connected")

            return True
        except Exception as e:
            if self.on_error:
                self.on_error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Close connection to the hub server."""
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

        if self.on_status_change:
            self.on_status_change("disconnected")

    def join_room(self, room_name: str, encryption_key: str) -> bool:
        """
        Join a room with password-based authentication.

        Authentication flow:
        1. Send JOIN_ROOM request
        2. Hub responds with AUTH_CHALLENGE
        3. Client signs challenge with password-derived key
        4. Send AUTH_RESPONSE
        5. Hub verifies and sends AUTH_SUCCESS or AUTH_FAILURE

        Args:
            room_name: Name of the room to join
            encryption_key: Password for this room

        Returns:
            True if join request sent successfully (auth happens asynchronously)
        """
        with self.lock:
            if room_name in self.rooms:
                if self.on_error:
                    self.on_error(f"Already in room: {room_name}")
                return False

            if not self.connected:
                if self.on_error:
                    self.on_error("Not connected to hub")
                return False

            try:
                # Create room context (stores password for authentication and encryption)
                self.rooms[room_name] = RoomContext(
                    name=room_name,
                    encryption_key=encryption_key,
                    last_activity=time.time()
                )

                # Send join request (hub will respond with challenge)
                packet = ClipProtocol.pack(room_name, b'', PacketType.JOIN_ROOM)
                self.sock.sendall(packet)

                # Note: Room isn't fully joined yet - waiting for auth
                # The receiver thread will handle the challenge-response
                return True
            except Exception as e:
                # Remove room on failure
                if room_name in self.rooms:
                    del self.rooms[room_name]
                if self.on_error:
                    self.on_error(f"Failed to join room: {e}")
                return False

    def leave_room(self, room_name: str) -> bool:
        """
        Leave a room.

        Args:
            room_name: Name of the room to leave

        Returns:
            True if successfully left
        """
        with self.lock:
            if room_name not in self.rooms:
                if self.on_error:
                    self.on_error(f"Not in room: {room_name}")
                return False

            if not self.connected:
                # Just remove locally if not connected
                del self.rooms[room_name]
                return True

            try:
                # Send LEAVE packet to hub
                packet = ClipProtocol.pack(room_name, b'', PacketType.LEAVE_ROOM)
                self.sock.sendall(packet)

                # Remove from local list
                del self.rooms[room_name]

                if self.on_room_change:
                    self.on_room_change('leave', room_name)

                return True
            except Exception as e:
                if self.on_error:
                    self.on_error(f"Failed to leave room: {e}")
                return False

    def recv_all(self, n: int) -> Optional[bytes]:
        """
        Receive exactly n bytes from the socket.

        TCP is a stream protocol - data might arrive in multiple chunks.
        This method ensures we get all the bytes we're expecting.

        Args:
            n: Number of bytes to receive

        Returns:
            Bytes received, or None if connection closed
        """
        if not self.sock:
            return None

        data = b''
        while len(data) < n:
            try:
                packet = self.sock.recv(n - len(data))
                if not packet:
                    return None  # Connection closed
                data += packet
            except socket.timeout:
                continue
            except Exception:
                return None
        return data

    def _add_received_hash(self, hash_val: str):
        """
        Track a received clipboard hash to prevent echo.

        When we receive clipboard data from a room, we track its hash.
        If we detect the same content in our local clipboard, we won't
        send it back to avoid an infinite loop.

        Args:
            hash_val: Hash of received clipboard content
        """
        self.received_hashes.add(hash_val)
        # Limit memory usage by removing old hashes
        if len(self.received_hashes) > self.max_received_hashes:
            # Remove one hash (arbitrary since it's a set)
            self.received_hashes.pop()

    def _monitor_loop(self):
        """
        Background thread: Monitor local clipboard and send changes to all rooms.

        This thread runs continuously while the agent is active.
        It checks the clipboard every poll_interval seconds for changes.
        When it detects a change (e.g., user pressed Ctrl+C), it:
        1. Encrypts the clipboard data with each room's password
        2. Sends to all joined rooms
        3. Updates room statistics
        """
        while self.running:
            try:
                # Skip if not connected or no rooms
                if not self.connected or not self.rooms:
                    time.sleep(self.poll_interval)
                    continue

                # Check if clipboard changed since last check
                clipboard_data = self.clipboard_handler.get_if_changed()

                if clipboard_data and not clipboard_data.is_empty():
                    current_hash = clipboard_data.get_hash()

                    # Skip if this was recently received (prevent echo)
                    if current_hash in self.received_hashes:
                        time.sleep(self.poll_interval)
                        continue

                    # URL Security Check before sending
                    if self.enable_url_verification and clipboard_data.text and HAS_URL_VERIFICATION:
                        try:
                            verification = URLVerifier.verify_text(clipboard_data.text)
                            if verification['has_threats']:
                                # Log warning (non-blocking)
                                warning_msg = format_verification_warning(verification)
                                print(f"\n⚠️  WARNING: Sending clipboard with suspicious URLs")
                                print(f"Threat score: {verification['max_threat_score']}/100\n")

                                # Notify callback
                                if self.on_url_threat:
                                    self.on_url_threat("outgoing", verification)
                        except Exception as e:
                            # Don't fail if URL verification has issues
                            print(f"[!] URL verification error on send: {e}")
                            import traceback
                            traceback.print_exc()

                    # Send to all joined rooms
                    with self.lock:
                        for room_name, room_ctx in list(self.rooms.items()):
                            try:
                                # Step 1: Serialize clipboard to binary
                                clipboard_binary = clipboard_data.to_bytes()

                                # Step 2: Encrypt with room's password
                                encrypted = SecurityEngine.encrypt_binary(
                                    clipboard_binary,
                                    room_ctx.encryption_key
                                )

                                # Step 3: Pack into protocol message
                                packet = ClipProtocol.pack(
                                    room_name,
                                    encrypted,
                                    PacketType.CLIPBOARD_FORMATS
                                )

                                # Step 4: Send to hub
                                self.sock.sendall(packet)

                                # Update statistics
                                room_ctx.sync_count += 1
                                room_ctx.last_activity = time.time()

                                # Notify UI (if callback set)
                                if self.on_clipboard_send:
                                    self.on_clipboard_send(room_name, clipboard_data)

                            except Exception as e:
                                if self.on_error:
                                    self.on_error(f"Send to {room_name} failed: {e}")

                time.sleep(self.poll_interval)

            except Exception as e:
                if self.on_error:
                    self.on_error(f"Monitor error: {e}")
                time.sleep(self.poll_interval)

    def _receiver_loop(self):
        """
        Background thread: Receive clipboard updates from hub.

        This thread runs continuously while the agent is active.
        It receives messages from the hub and processes them:
        - AUTH_CHALLENGE: Sign with password and respond
        - AUTH_SUCCESS/FAILURE: Handle authentication result
        - CLIPBOARD_FORMATS: Decrypt and apply to local clipboard
        """
        while self.running:
            try:
                if not self.connected:
                    time.sleep(0.1)
                    continue

                # Step 1: Read message header
                header_data = self.recv_all(ClipProtocol.HEADER_SIZE)
                if not header_data:
                    # Connection closed
                    if self.running:
                        self.connected = False
                        if self.on_status_change:
                            self.on_status_change("disconnected")
                        if self.on_error:
                            self.on_error("Connection lost")
                    break

                # Step 2: Parse header
                magic, ver, packet_type, room_len, data_len = ClipProtocol.unpack_header(header_data)

                # Step 3: Read room name
                room_bytes = self.recv_all(room_len)
                if not room_bytes:
                    break
                room_name = room_bytes.decode('utf-8')

                # Step 4: Read payload
                encrypted_payload = self.recv_all(data_len)
                if not encrypted_payload:
                    break

                # Step 5: Handle message based on type
                if packet_type == PacketType.AUTH_CHALLENGE:
                    # Hub sent authentication challenge
                    with self.lock:
                        if room_name not in self.rooms:
                            continue

                        room_ctx = self.rooms[room_name]
                        challenge = encrypted_payload

                        # Sign challenge with password: HMAC(password_hash, challenge)
                        import hmac
                        import hashlib
                        key_hash = hashlib.sha256(room_ctx.encryption_key.encode()).digest()
                        response = hmac.new(key_hash, challenge, hashlib.sha256).digest()

                        # Send signed response back to hub
                        response_packet = ClipProtocol.pack(room_name, response, PacketType.AUTH_RESPONSE)
                        self.sock.sendall(response_packet)
                        continue

                elif packet_type == PacketType.AUTH_SUCCESS:
                    # Authentication successful - we're now in the room
                    if self.on_room_change:
                        self.on_room_change('join', room_name)
                    continue

                elif packet_type == PacketType.AUTH_FAILURE:
                    # Authentication failed - wrong password
                    with self.lock:
                        if room_name in self.rooms:
                            del self.rooms[room_name]
                    if self.on_error:
                        self.on_error(f"Failed to join room '{room_name}': Wrong password")
                    continue

                # Process clipboard data if we're in this room
                with self.lock:
                    if room_name not in self.rooms:
                        continue

                    room_ctx = self.rooms[room_name]

                    try:
                        # Step 1: Decrypt with room password (verifies auth tag)
                        decrypted_binary = SecurityEngine.decrypt_binary(
                            encrypted_payload,
                            room_ctx.encryption_key
                        )

                        # Step 2: Deserialize from binary format
                        clipboard_data = ClipboardData.from_bytes(decrypted_binary)

                        if clipboard_data.is_empty():
                            continue

                        # Step 2.5: URL Security Verification
                        if self.enable_url_verification and clipboard_data.text and HAS_URL_VERIFICATION:
                            try:
                                verification = URLVerifier.verify_text(clipboard_data.text)
                                if verification['has_threats']:
                                    # Found suspicious URLs
                                    warning_msg = format_verification_warning(verification)

                                    # Log warning
                                    if self.on_error:
                                        self.on_error(f"⚠️  URL THREAT DETECTED in clipboard from room '{room_name}'")

                                    # Notify via callback
                                    if self.on_url_threat:
                                        self.on_url_threat(room_name, verification)

                                    # Print warning to console
                                    print(f"\n{warning_msg}\n")

                                    # Optional: Block dangerous URLs (score >= 80)
                                    if verification['max_threat_score'] >= 80:
                                        print(f"[!] BLOCKING dangerous clipboard content from room '{room_name}'")
                                        print(f"[!] Threat score: {verification['max_threat_score']}/100")
                                        continue  # Skip updating clipboard
                            except Exception as e:
                                # Don't fail if URL verification has issues
                                print(f"[!] URL verification error: {e}")
                                import traceback
                                traceback.print_exc()

                        # Step 3: Track hash to prevent echo
                        current_hash = clipboard_data.get_hash()
                        self._add_received_hash(current_hash)

                        # Step 4: Update local clipboard
                        self.clipboard_handler.set_clipboard(clipboard_data)

                        # Update statistics
                        room_ctx.sync_count += 1
                        room_ctx.last_activity = time.time()
                        room_ctx.last_hash = current_hash

                        # Notify UI (if callback set)
                        if self.on_clipboard_receive:
                            self.on_clipboard_receive(room_name, clipboard_data)

                    except Exception as e:
                        if self.on_error:
                            # Could be wrong password or tampered data
                            self.on_error(f"Decrypt failed for {room_name}: {e}")

            except Exception as e:
                if self.running and self.on_error:
                    self.on_error(f"Receiver error: {e}")
                time.sleep(0.1)

    def start(self) -> bool:
        """
        Start the clipboard agent.

        This will:
        1. Connect to the hub server
        2. Start the monitor thread (watches clipboard for changes)
        3. Start the receiver thread (receives updates from hub)

        Returns:
            True if started successfully, False if connection failed
        """
        if self.running:
            return True

        if not self.connect():
            return False

        self.running = True

        # Start clipboard monitor thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ClipboardMonitor",
            daemon=True  # Thread will exit when main program exits
        )

        # Start message receiver thread
        self._receiver_thread = threading.Thread(
            target=self._receiver_loop,
            name="ClipboardReceiver",
            daemon=True
        )

        self._monitor_thread.start()
        self._receiver_thread.start()

        return True

    def stop(self):
        """
        Stop the clipboard agent.

        Disconnects from hub and clears all rooms.
        The background threads will exit automatically.
        """
        self.running = False
        self.disconnect()

        # Clear all rooms
        with self.lock:
            self.rooms.clear()

    def get_rooms_info(self) -> Dict[str, dict]:
        """
        Get information about all joined rooms (for UI display).

        Returns:
            Dictionary mapping room names to their stats
        """
        with self.lock:
            return {
                name: {
                    'sync_count': room.sync_count,
                    'last_activity': room.last_activity,
                }
                for name, room in self.rooms.items()
            }

    def get_room_count(self) -> int:
        """Get the number of rooms currently joined."""
        with self.lock:
            return len(self.rooms)

    def is_in_room(self, room_name: str) -> bool:
        """
        Check if agent is in a specific room.

        Args:
            room_name: Name of the room to check

        Returns:
            True if currently in this room
        """
        with self.lock:
            return room_name in self.rooms
