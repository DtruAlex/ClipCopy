"""
Multi-room clipboard synchronization server.

This is the central hub that routes encrypted clipboard data between clients.
The hub never decrypts data - it only verifies that clients know the room password
and then relays encrypted messages between clients in the same room.

Key Features:
- Multiple isolated rooms (like chat rooms)
- Password authentication using challenge-response
- End-to-end encryption (hub never sees plaintext)
- Binary protocol for efficiency
"""
import socket
import threading
import os
from ClipProtocol import ClipProtocol, PacketType


class ClipHub:
    """
    Central server for clipboard synchronization.

    Acts as a relay that routes encrypted clipboard data between clients
    in the same room. The hub never decrypts clipboard data.

    Authentication:
    - First client to join a room sets the password
    - Subsequent clients must prove they know the same password
    - Uses challenge-response to verify without transmitting password
    """

    def __init__(self, host='127.0.0.1', port=9999):
        # Setup network socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)

        # Room management
        # Maps room name to list of connected client sockets
        self.rooms = {}

        # Maps client socket to set of room names they've joined
        self.client_rooms = {}

        # Password verification data for each room
        # Maps room name to {'challenge': bytes, 'response': bytes}
        # This stores the challenge and expected response for authentication
        self.room_password_hashes = {}

        # Temporary storage for ongoing authentication attempts
        # Maps client socket to {'room': str, 'challenge': bytes}
        self.pending_challenges = {}

        # Thread safety lock
        self.lock = threading.Lock()

        print(f"[*] Multi-Room Clipboard Hub initialized on {host}:{port}")
        print(f"[*] Using AES-256-GCM encryption (clients encrypt/decrypt)")
        print(f"[*] Challenge-response authentication enabled")
        print(f"[*] Binary protocol (no JSON overhead)")

    def send_auth_challenge(self, client_socket, room_name):
        """
        Send authentication challenge to client.

        For new rooms: Generate a random challenge
        For existing rooms: Reuse the stored challenge (so we can verify responses match)
        """
        with self.lock:
            if room_name in self.room_password_hashes:
                # Room exists - reuse the challenge so we can verify password match
                challenge = self.room_password_hashes[room_name]['challenge']
                print(f"[🔐] Sending stored challenge for room '{room_name}' (verification)")
            else:
                # New room - generate random challenge
                challenge = os.urandom(32)
                print(f"[🔐] Sending new challenge for room '{room_name}' (first client)")

            # Store pending challenge for this client
            self.pending_challenges[client_socket] = {
                "room": room_name,
                "challenge": challenge
            }

        # Send challenge packet to client
        packet = ClipProtocol.pack(room_name, challenge, PacketType.AUTH_CHALLENGE)
        client_socket.sendall(packet)

    def verify_auth_response(self, client_socket, room_name, response):
        """
        Verify client's authentication response using HMAC.

        How it works:
        1. Hub sends challenge (random bytes)
        2. Client computes: HMAC(password_hash, challenge)
        3. Hub checks if response matches expected value

        For first client: Store their response as the "correct" answer
        For later clients: Verify their response matches the first client's

        This proves all clients know the same password without transmitting it!

        Args:
            client_socket: The client attempting to join
            room_name: Name of the room they're joining
            response: The HMAC response from the client

        Returns:
            True if authentication succeeds, False otherwise
        """
        with self.lock:
            # Verify we have a pending challenge for this client
            if client_socket not in self.pending_challenges:
                print(f"[!] No pending challenge for client")
                return False

            challenge_data = self.pending_challenges[client_socket]

            # Verify the room name matches
            if challenge_data["room"] != room_name:
                print(f"[!] Room mismatch in auth response")
                del self.pending_challenges[client_socket]
                return False

            challenge = challenge_data["challenge"]

            # First client joining this room - establish the password
            if room_name not in self.room_password_hashes:
                # Store the challenge and response
                # Future clients must provide the same response to the same challenge
                self.room_password_hashes[room_name] = {
                    'challenge': challenge,
                    'response': response
                }
                del self.pending_challenges[client_socket]
                print(f"[🔑] Room '{room_name}' password established (first client)")
                return True

            # Verify subsequent clients
            stored_data = self.room_password_hashes[room_name]
            stored_response = stored_data['response']

            # Clean up pending challenge
            del self.pending_challenges[client_socket]

            # Compare the responses - they should match if same password
            if response == stored_response:
                print(f"[✅] Auth successful for room '{room_name}'")
                return True
            else:
                print(f"[❌] Auth failed for room '{room_name}' (wrong password)")
                return False

    def join_room(self, client_socket, room_name):
        """
        Add a client to a room (after successful authentication).

        Args:
            client_socket: The authenticated client's socket
            room_name: Name of the room to join
        """
        with self.lock:
            # Add to room registry
            if room_name not in self.rooms:
                self.rooms[room_name] = []
            if client_socket not in self.rooms[room_name]:
                self.rooms[room_name].append(client_socket)

            # Track which rooms this client is in
            if client_socket not in self.client_rooms:
                self.client_rooms[client_socket] = set()
            self.client_rooms[client_socket].add(room_name)

            room_count = len(self.client_rooms[client_socket])
            clients_in_room = len(self.rooms[room_name])
            print(f"[+] Client joined room '{room_name}' (now in {room_count} room(s), {clients_in_room} clients in room)")

    def leave_room(self, client_socket, room_name):
        """
        Remove a client from a room.

        Args:
            client_socket: The client's socket
            room_name: Name of the room to leave
        """
        with self.lock:
            # Remove from room
            if room_name in self.rooms and client_socket in self.rooms[room_name]:
                self.rooms[room_name].remove(client_socket)
                print(f"[-] Client left room '{room_name}'")

                # Clean up empty rooms to save memory
                if not self.rooms[room_name]:
                    del self.rooms[room_name]
                    print(f"[*] Room '{room_name}' is now empty (removed)")

            # Update client's room list
            if client_socket in self.client_rooms:
                self.client_rooms[client_socket].discard(room_name)

    def broadcast(self, room_name, packet, sender_socket):
        """
        Send encrypted clipboard data to all clients in a room (except the sender).

        The hub never decrypts the data - it just relays the encrypted packet
        to all other clients in the same room.

        Args:
            room_name: Name of the room to broadcast to
            packet: Complete encrypted packet to send
            sender_socket: The client who sent this data (won't receive it back)
        """
        with self.lock:
            if room_name in self.rooms:
                sent_count = 0
                stale_sockets = []

                # Send to each client in the room (except sender)
                for client in self.rooms[room_name]:
                    if client is not sender_socket:
                        try:
                            client.sendall(packet)
                            sent_count += 1
                        except Exception as e:
                            print(f"[!] Failed to send to client: {e}")
                            stale_sockets.append(client)

                # Remove disconnected clients
                for stale in stale_sockets:
                    self.rooms[room_name].remove(stale)
                    if stale in self.client_rooms:
                        del self.client_rooms[stale]

                if sent_count > 0:
                    print(f"[📤] Broadcasted to {sent_count} client(s) in '{room_name}'")

    def handle_client(self, client_socket, addr):
        """
        Handle all communication with a connected client.

        This method runs in a separate thread for each client.
        It receives messages, processes them based on type, and handles cleanup.

        Message handling flow:
        1. Client sends JOIN_ROOM request
        2. Hub sends AUTH_CHALLENGE
        3. Client sends AUTH_RESPONSE
        4. Hub verifies and sends AUTH_SUCCESS or AUTH_FAILURE
        5. If successful, client can send/receive clipboard data

        Args:
            client_socket: The client's network socket
            addr: Client's address (for logging)
        """
        print(f"[*] Client {addr} connected")

        try:
            while True:
                # Step 1: Read the message header (11 bytes)
                header_data = self.recv_all(client_socket, ClipProtocol.HEADER_SIZE)
                if not header_data:
                    break  # Connection closed

                # Step 2: Parse the header
                magic, ver, packet_type, room_len, data_len = ClipProtocol.unpack_header(header_data)

                # Step 3: Validate magic bytes (protocol verification)
                if magic != ClipProtocol.MAGIC:
                    print(f"[!] Invalid magic bytes from {addr}")
                    break

                # Step 4: Read room name
                room_name = self.recv_all(client_socket, room_len).decode('utf-8')

                # Step 5: Read data payload
                payload = self.recv_all(client_socket, data_len)

                # Step 6: Handle message based on type
                if packet_type == PacketType.JOIN_ROOM:
                    # Client wants to join - send authentication challenge
                    self.send_auth_challenge(client_socket, room_name)

                elif packet_type == PacketType.AUTH_RESPONSE:
                    # Client responded to challenge - verify password
                    if self.verify_auth_response(client_socket, room_name, payload):
                        # Authentication successful
                        self.join_room(client_socket, room_name)
                        success_packet = ClipProtocol.pack(room_name, b'OK', PacketType.AUTH_SUCCESS)
                        client_socket.sendall(success_packet)
                    else:
                        # Authentication failed
                        failure_packet = ClipProtocol.pack(room_name, b'FAIL', PacketType.AUTH_FAILURE)
                        client_socket.sendall(failure_packet)

                elif packet_type == PacketType.LEAVE_ROOM:
                    # Client wants to leave a room
                    self.leave_room(client_socket, room_name)

                elif packet_type in (PacketType.DATA, PacketType.CLIPBOARD_FORMATS):
                    # Client is sending clipboard data
                    # Verify they're actually in this room before relaying
                    if client_socket in self.client_rooms and \
                       room_name in self.client_rooms.get(client_socket, set()):
                        # Broadcast encrypted data to other clients in room
                        full_packet = header_data + room_name.encode('utf-8') + payload
                        self.broadcast(room_name, full_packet, client_socket)
                    else:
                        print(f"[!] Client {addr} attempted to send to room '{room_name}' without joining")

        except Exception as e:
            print(f"[!] Client {addr} error: {e}")
        finally:
            # Cleanup: Remove client from all rooms when they disconnect
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
        """
        Receive exactly n bytes from a socket.

        TCP doesn't guarantee all data arrives in one packet, so we need
        to keep reading until we have all the bytes we expect.

        Args:
            sock: Socket to read from
            n: Number of bytes to receive

        Returns:
            Bytes received, or None if connection closed
        """
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None  # Connection closed
            data += packet
        return data

    def run(self):
        """
        Main server loop - accepts incoming connections.

        Runs forever until interrupted with Ctrl+C.
        Each client connection is handled in a separate thread.
        """
        print("[*] Waiting for clients...")
        print("[*] Press Ctrl+C to stop")
        try:
            while True:
                # Accept new client connection
                client_sock, addr = self.server_socket.accept()

                # Create a new thread to handle this client
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr),
                    daemon=True  # Thread dies when main program exits
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
