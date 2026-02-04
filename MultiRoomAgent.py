"""
Multi-room clipboard synchronization agent with AES-256-GCM encryption.
Automatically syncs clipboard changes (Ctrl+C) across all joined rooms.
Uses pure binary serialization and authenticated encryption.
"""
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Callable, Set

from ClipProtocol import ClipProtocol, PacketType
from clipboard_handler import ClipboardHandler, ClipboardData
from utils import SecurityEngine


@dataclass
class RoomContext:
    """Context for a single room"""
    name: str
    encryption_key: str
    last_hash: str = ""      # Hash of last clipboard from this room (prevents echo)
    sync_count: int = 0      # Number of syncs (for stats)
    last_activity: float = 0.0  # Timestamp of last activity


class MultiRoomAgent:
    """
    Clipboard agent that supports multiple rooms with rich clipboard.

    Features:
    - Join/leave multiple rooms dynamically
    - Automatic clipboard monitoring (polls every 500ms)
    - Rich clipboard support (text, images, HTML, etc.)
    - Per-room encryption
    - Echo prevention (won't re-send received content)
    """

    def __init__(self, hub_host: str = '127.0.0.1', hub_port: int = 9999,
                 poll_interval: float = 0.1):
        self.hub_host = hub_host
        self.hub_port = hub_port
        self.poll_interval = poll_interval

        self.sock: Optional[socket.socket] = None
        self.rooms: Dict[str, RoomContext] = {}
        self.clipboard_handler = ClipboardHandler()
        self.running = False
        self.connected = False
        self.lock = threading.RLock()

        # Set of hashes we recently received (to prevent echo)
        self.received_hashes: Set[str] = set()
        self.max_received_hashes = 100  # Limit memory usage

        # Callbacks for TUI integration
        self.on_clipboard_send: Optional[Callable[[str, ClipboardData], None]] = None
        self.on_clipboard_receive: Optional[Callable[[str, ClipboardData], None]] = None
        self.on_room_change: Optional[Callable[[str, str], None]] = None  # (action, room_name)
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_status_change: Optional[Callable[[str], None]] = None  # (status)

    def connect(self) -> bool:
        """Connect to the hub server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0)  # Connection timeout
            self.sock.connect((self.hub_host, self.hub_port))
            self.sock.settimeout(None)  # Disable timeout for normal ops
            self.connected = True

            if self.on_status_change:
                self.on_status_change("connected")

            return True
        except Exception as e:
            if self.on_error:
                self.on_error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from the hub"""
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
        """Join a new room with authentication"""
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
                # Store room context with encryption key (auth pending)
                self.rooms[room_name] = RoomContext(
                    name=room_name,
                    encryption_key=encryption_key,
                    last_activity=time.time()
                )

                # Send JOIN packet (hub will respond with challenge)
                packet = ClipProtocol.pack(room_name, b'', PacketType.JOIN_ROOM)
                self.sock.sendall(packet)

                # Note: Room is not fully joined yet - waiting for auth challenge
                # The receiver loop will handle the challenge-response

                return True
            except Exception as e:
                # Remove room on failure
                if room_name in self.rooms:
                    del self.rooms[room_name]
                if self.on_error:
                    self.on_error(f"Failed to join room: {e}")
                return False

    def leave_room(self, room_name: str) -> bool:
        """Leave a room"""
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
                # Send LEAVE packet
                packet = ClipProtocol.pack(room_name, b'', PacketType.LEAVE_ROOM)
                self.sock.sendall(packet)

                # Remove from local registry
                del self.rooms[room_name]

                if self.on_room_change:
                    self.on_room_change('leave', room_name)

                return True
            except Exception as e:
                if self.on_error:
                    self.on_error(f"Failed to leave room: {e}")
                return False

    def recv_all(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes from socket"""
        if not self.sock:
            return None

        data = b''
        while len(data) < n:
            try:
                packet = self.sock.recv(n - len(data))
                if not packet:
                    return None
                data += packet
            except socket.timeout:
                continue
            except Exception:
                return None
        return data

    def _add_received_hash(self, hash_val: str):
        """Track received clipboard hashes to prevent echo"""
        self.received_hashes.add(hash_val)
        # Limit memory usage
        if len(self.received_hashes) > self.max_received_hashes:
            # Remove oldest (arbitrary since it's a set)
            self.received_hashes.pop()

    def _monitor_loop(self):
        """Background thread: Monitor clipboard and sync to all rooms"""
        while self.running:
            try:
                if not self.connected or not self.rooms:
                    time.sleep(self.poll_interval)
                    continue

                # Check if clipboard changed
                clipboard_data = self.clipboard_handler.get_if_changed()

                if clipboard_data and not clipboard_data.is_empty():
                    current_hash = clipboard_data.get_hash()

                    # Skip if this was recently received (prevent echo)
                    if current_hash in self.received_hashes:
                        time.sleep(self.poll_interval)
                        continue

                    # Send to all joined rooms
                    with self.lock:
                        for room_name, room_ctx in list(self.rooms.items()):
                            try:
                                # Serialize clipboard data to pure binary
                                clipboard_binary = clipboard_data.to_bytes()

                                # Encrypt with AES-256-GCM (includes auth tag)
                                encrypted = SecurityEngine.encrypt_binary(
                                    clipboard_binary,
                                    room_ctx.encryption_key
                                )

                                # Send packet
                                packet = ClipProtocol.pack(
                                    room_name,
                                    encrypted,
                                    PacketType.CLIPBOARD_FORMATS
                                )
                                self.sock.sendall(packet)

                                # Update room stats
                                room_ctx.sync_count += 1
                                room_ctx.last_activity = time.time()

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
        """Background thread: Receive clipboard updates from hub"""
        while self.running:
            try:
                if not self.connected:
                    time.sleep(0.1)
                    continue

                # Read header
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

                magic, ver, p_type, r_len, d_len = ClipProtocol.unpack_header(header_data)

                # Read room name
                room_bytes = self.recv_all(r_len)
                if not room_bytes:
                    break
                room_name = room_bytes.decode('utf-8')

                # Read payload
                encrypted_payload = self.recv_all(d_len)
                if not encrypted_payload:
                    break

                # Handle authentication packets
                if p_type == PacketType.AUTH_CHALLENGE:
                    # Hub sent us a challenge - we need to sign it with our room key
                    with self.lock:
                        if room_name not in self.rooms:
                            continue

                        room_ctx = self.rooms[room_name]
                        challenge = encrypted_payload

                        # Sign challenge with room key: HMAC(key, challenge)
                        import hmac
                        import hashlib
                        key_hash = hashlib.sha256(room_ctx.encryption_key.encode()).digest()
                        response = hmac.new(key_hash, challenge, hashlib.sha256).digest()

                        # Send response back
                        response_packet = ClipProtocol.pack(room_name, response, PacketType.AUTH_RESPONSE)
                        self.sock.sendall(response_packet)
                        continue

                elif p_type == PacketType.AUTH_SUCCESS:
                    # Authentication successful - we're now in the room
                    if self.on_room_change:
                        self.on_room_change('join', room_name)
                    continue

                elif p_type == PacketType.AUTH_FAILURE:
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
                        # Decrypt with AES-256-GCM (verifies auth tag)
                        # Will raise exception if authentication fails
                        decrypted_binary = SecurityEngine.decrypt_binary(
                            encrypted_payload,
                            room_ctx.encryption_key
                        )

                        # Deserialize from pure binary format
                        clipboard_data = ClipboardData.from_bytes(decrypted_binary)

                        if clipboard_data.is_empty():
                            continue

                        # Track hash to prevent echo
                        current_hash = clipboard_data.get_hash()
                        self._add_received_hash(current_hash)

                        # Update local clipboard
                        self.clipboard_handler.set_clipboard(clipboard_data)

                        # Update room stats
                        room_ctx.sync_count += 1
                        room_ctx.last_activity = time.time()
                        room_ctx.last_hash = current_hash

                        if self.on_clipboard_receive:
                            self.on_clipboard_receive(room_name, clipboard_data)

                    except Exception as e:
                        if self.on_error:
                            # This could be authentication failure (wrong key/tampered data)
                            self.on_error(f"Decrypt failed for {room_name}: {e}")

            except Exception as e:
                if self.running and self.on_error:
                    self.on_error(f"Receiver error: {e}")
                time.sleep(0.1)

    def start(self) -> bool:
        """Start the agent (connect and start background threads)"""
        if self.running:
            return True

        if not self.connect():
            return False

        self.running = True

        # Start monitor thread (watches clipboard, sends changes)
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ClipboardMonitor",
            daemon=True
        )

        # Start receiver thread (receives changes from others)
        self._receiver_thread = threading.Thread(
            target=self._receiver_loop,
            name="ClipboardReceiver",
            daemon=True
        )

        self._monitor_thread.start()
        self._receiver_thread.start()

        return True

    def stop(self):
        """Stop the agent"""
        self.running = False
        self.disconnect()

        # Clear rooms
        with self.lock:
            self.rooms.clear()

    def get_rooms_info(self) -> Dict[str, dict]:
        """Get info about all rooms (for TUI display)"""
        with self.lock:
            return {
                name: {
                    'sync_count': room.sync_count,
                    'last_activity': room.last_activity,
                }
                for name, room in self.rooms.items()
            }

    def get_room_count(self) -> int:
        """Get number of joined rooms"""
        with self.lock:
            return len(self.rooms)

    def is_in_room(self, room_name: str) -> bool:
        """Check if agent is in a specific room"""
        with self.lock:
            return room_name in self.rooms
