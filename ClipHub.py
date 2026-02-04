"""
Multi-room clipboard synchronization hub with AES-256-GCM support.
This is the server/relay that routes encrypted clipboard data between clients.
Implements challenge-response authentication to prevent unauthorized room access.
"""
import socket
import threading
import os
import hashlib
import hmac
from ClipProtocol import ClipProtocol, PacketType


class ClipHub:
    """
    Multi-room clipboard synchronization hub with authentication.

    Acts as a relay server that routes encrypted clipboard data
    between clients in the same room. The hub never decrypts data.

    Security: Uses challenge-response authentication to verify clients
    know the room password before allowing them to join.
    """

    def __init__(self, host='0.0.0.0', port=9999):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)

        # Room Registry: { "room_name": [socket1, socket2, ...] }
        self.rooms = {}

        # Client to Rooms mapping: { socket: set("room1", "room2", ...) }
        self.client_rooms = {}

        # Room Password Hashes: { "room_name": sha256_hash }
        # First client to join sets the password hash
        self.room_password_hashes = {}

        # Pending auth challenges: { socket: {"room": str, "challenge": bytes} }
        self.pending_challenges = {}

        self.lock = threading.Lock()

        print(f"[*] Multi-Room Clipboard Hub initialized on {host}:{port}")
        print(f"[*] Using AES-256-GCM encryption (clients encrypt/decrypt)")
        print(f"[*] Challenge-response authentication enabled")
        print(f"[*] Binary protocol (no JSON overhead)")

    def send_auth_challenge(self, client_socket, room_name):
        """Send authentication challenge to client"""
        with self.lock:
            # For existing rooms, reuse the stored challenge
            # This allows us to verify if clients produce the same HMAC signature
            if room_name in self.room_password_hashes:
                challenge = self.room_password_hashes[room_name]['challenge']
                print(f"[🔐] Sending stored challenge for room '{room_name}' (verification)")
            else:
                # For new rooms, generate random challenge
                challenge = os.urandom(32)
                print(f"[🔐] Sending new challenge for room '{room_name}' (first client)")

            # Store pending challenge
            self.pending_challenges[client_socket] = {
                "room": room_name,
                "challenge": challenge
            }

        # Send challenge packet
        packet = ClipProtocol.pack(room_name, challenge, PacketType.AUTH_CHALLENGE)
        client_socket.sendall(packet)

    def verify_auth_response(self, client_socket, room_name, response):
        """Verify client's authentication response using HMAC"""
        with self.lock:
            # Check if we have a pending challenge for this socket
            if client_socket not in self.pending_challenges:
                print(f"[!] No pending challenge for client")
                return False

            challenge_data = self.pending_challenges[client_socket]

            # Verify room matches
            if challenge_data["room"] != room_name:
                print(f"[!] Room mismatch in auth response")
                del self.pending_challenges[client_socket]
                return False

            challenge = challenge_data["challenge"]

            # For first client joining room, store their password-derived key hash
            # by extracting it from their HMAC response
            if room_name not in self.room_password_hashes:
                # First client sets the password
                # We store the hash of their derived key (which was used in HMAC)
                # Since we have: response = HMAC(key_hash, challenge)
                # We can't reverse HMAC, but we can store response and verify
                # future clients produce same response to same challenge

                # Better approach: Store the password hash from the response
                # by storing the response itself and re-using same challenge for verification

                # Actually, we need to store the PASSWORD HASH, not the response
                # The response is HMAC(password_hash, challenge)
                # We can verify by checking if new clients produce matching HMAC

                # Store the password hash by having client send it directly in first join
                # For now, let's use a simpler approach: trust first client and verify
                # subsequent clients by having them prove they know the same password

                # Solution: Store the response, and for subsequent clients,
                # send the SAME challenge and verify they produce SAME response
                self.room_password_hashes[room_name] = {
                    'challenge': challenge,
                    'response': response
                }
                del self.pending_challenges[client_socket]
                print(f"[🔑] Room '{room_name}' password established (first client)")
                return True

            # For subsequent clients, verify they produce the same response
            # to the same challenge that the first client received
            stored_data = self.room_password_hashes[room_name]
            stored_challenge = stored_data['challenge']
            stored_response = stored_data['response']

            # We need to re-send the STORED challenge to verify
            # But we already sent a random challenge! This won't work.

            # Better approach: Use the SAME challenge for all verifications
            # Or: Compare if response was created with same key

            # Since challenge was already sent (random), we need different approach:
            # Send the STORED challenge to new clients instead of random one!
            # Let's fix send_auth_challenge to use stored challenge if room exists

            # For now, let's use a workaround: verify HMAC structure
            # We know: response = HMAC(password_hash, challenge)
            # We can't verify without knowing password_hash

            # Simplest fix: Make the challenge deterministic for a room
            # Or: Send same challenge that was sent to first client

            # Let's compare if challenge was the stored one
            if challenge != stored_challenge:
                # New challenge was sent, need to verify differently
                # This means we need to fix send_auth_challenge to reuse
                # stored challenge for existing rooms
                print(f"[!] Different challenge used - verification not possible")
                del self.pending_challenges[client_socket]
                return False

            # Same challenge - verify response matches
            if response == stored_response:
                del self.pending_challenges[client_socket]
                print(f"[✅] Auth successful for room '{room_name}'")
                return True
            else:
                del self.pending_challenges[client_socket]
                print(f"[❌] Auth failed for room '{room_name}' (wrong password)")
                return False

    def join_room(self, client_socket, room_name):
        """Add client to a room"""
        with self.lock:
            # Add to room registry
            if room_name not in self.rooms:
                self.rooms[room_name] = []
            if client_socket not in self.rooms[room_name]:
                self.rooms[room_name].append(client_socket)

            # Track client's rooms
            if client_socket not in self.client_rooms:
                self.client_rooms[client_socket] = set()
            self.client_rooms[client_socket].add(room_name)

            room_count = len(self.client_rooms[client_socket])
            clients_in_room = len(self.rooms[room_name])
            print(f"[+] Client joined room '{room_name}' (now in {room_count} room(s), {clients_in_room} clients in room)")

    def leave_room(self, client_socket, room_name):
        """Remove client from a room"""
        with self.lock:
            if room_name in self.rooms and client_socket in self.rooms[room_name]:
                self.rooms[room_name].remove(client_socket)
                print(f"[-] Client left room '{room_name}'")

                # Clean up empty rooms
                if not self.rooms[room_name]:
                    del self.rooms[room_name]
                    print(f"[*] Room '{room_name}' is now empty (removed)")

            if client_socket in self.client_rooms:
                self.client_rooms[client_socket].discard(room_name)

    def broadcast(self, room_name, packet, sender_socket):
        """
        Relay encrypted clipboard data to all clients in the room except sender.
        Hub never decrypts - just relays the encrypted binary data.
        """
        with self.lock:
            if room_name in self.rooms:
                sent_count = 0
                stale_sockets = []

                for client in self.rooms[room_name]:
                    if client is not sender_socket:
                        try:
                            client.sendall(packet)
                            sent_count += 1
                        except Exception as e:
                            print(f"[!] Failed to send to client: {e}")
                            stale_sockets.append(client)

                # Cleanup disconnected clients
                for stale in stale_sockets:
                    self.rooms[room_name].remove(stale)
                    if stale in self.client_rooms:
                        del self.client_rooms[stale]

                if sent_count > 0:
                    print(f"[📤] Broadcasted to {sent_count} client(s) in '{room_name}'")

    def handle_client(self, client_socket, addr):
        """Handle multi-room client connection"""
        print(f"[*] Client {addr} connected")

        try:
            while True:
                # Read header (11 bytes)
                header_data = self.recv_all(client_socket, ClipProtocol.HEADER_SIZE)
                if not header_data:
                    break

                magic, ver, p_type, r_len, d_len = ClipProtocol.unpack_header(header_data)

                # Validate magic bytes
                if magic != ClipProtocol.MAGIC:
                    print(f"[!] Invalid magic bytes from {addr}")
                    break

                # Extract room name
                room_name = self.recv_all(client_socket, r_len).decode('utf-8')

                # Extract payload (encrypted data)
                payload = self.recv_all(client_socket, d_len)

                # Handle different packet types
                if p_type == PacketType.JOIN_ROOM:
                    # Send authentication challenge instead of immediately joining
                    self.send_auth_challenge(client_socket, room_name)

                elif p_type == PacketType.AUTH_RESPONSE:
                    # Verify authentication response
                    if self.verify_auth_response(client_socket, room_name, payload):
                        # Auth successful - join the room
                        self.join_room(client_socket, room_name)
                        # Send success confirmation
                        success_packet = ClipProtocol.pack(room_name, b'OK', PacketType.AUTH_SUCCESS)
                        client_socket.sendall(success_packet)
                    else:
                        # Auth failed - send failure
                        failure_packet = ClipProtocol.pack(room_name, b'FAIL', PacketType.AUTH_FAILURE)
                        client_socket.sendall(failure_packet)

                elif p_type == PacketType.LEAVE_ROOM:
                    self.leave_room(client_socket, room_name)

                elif p_type in (PacketType.DATA, PacketType.CLIPBOARD_FORMATS):
                    # Only allow data if client is in the room
                    if client_socket in self.client_rooms and \
                       room_name in self.client_rooms.get(client_socket, set()):
                        # Broadcast encrypted data to room (hub never decrypts)
                        full_packet = header_data + room_name.encode('utf-8') + payload
                        self.broadcast(room_name, full_packet, client_socket)
                    else:
                        print(f"[!] Client {addr} attempted to send to room '{room_name}' without joining")

        except Exception as e:
            print(f"[!] Client {addr} error: {e}")
        finally:
            # Cleanup: remove client from all rooms
            print(f"[*] Client {addr} disconnected")
            with self.lock:
                if client_socket in self.client_rooms:
                    for room_name in list(self.client_rooms[client_socket]):
                        if room_name in self.rooms and client_socket in self.rooms[room_name]:
                            self.rooms[room_name].remove(client_socket)
                        print(f"[-] Client removed from room '{room_name}'")
                    del self.client_rooms[client_socket]
            client_socket.close()

    def recv_all(self, sock, n):
        """Receive exactly n bytes from socket"""
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def run(self):
        """Main server loop"""
        print("[*] Waiting for clients...")
        print("[*] Press Ctrl+C to stop")
        try:
            while True:
                client_sock, addr = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down hub...")
        finally:
            self.server_socket.close()


if __name__ == "__main__":
    import sys

    # Parse command line arguments
    host = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

    hub = ClipHub(host=host, port=port)
    hub.run()
