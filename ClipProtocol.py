"""
Network protocol for clipboard synchronization.

Defines the binary message format used for communication between clients and the hub.
"""

import struct


class PacketType:
    """
    Message type identifiers for the clipboard protocol.

    Each packet has a type that tells the receiver what kind of message it is.
    """
    DATA = 0x01              # Simple text clipboard data (legacy)
    HANDSHAKE = 0x02         # Initial connection handshake
    JOIN_ROOM = 0x05         # Request to join a room
    LEAVE_ROOM = 0x06        # Request to leave a room
    CLIPBOARD_FORMATS = 0x08 # Rich clipboard data (text, images, HTML, etc.)
    AUTH_CHALLENGE = 0x09    # Server sends password verification challenge
    AUTH_RESPONSE = 0x0A     # Client responds to authentication challenge
    AUTH_SUCCESS = 0x0B      # Server confirms successful authentication
    AUTH_FAILURE = 0x0C      # Server rejects authentication (wrong password)


class ClipProtocol:
    """
    Binary protocol for clipboard synchronization messages.

    Every message has this structure:
    1. Header (11 bytes): Contains metadata about the message
    2. Room name: Name of the room this message is for
    3. Data payload: The actual content (encrypted clipboard data, etc.)

    Header Format (11 bytes total):
    ┌──────────────┬─────────┬──────┬──────────┬──────────┐
    │ MAGIC        │ VERSION │ TYPE │ ROOM_LEN │ DATA_LEN │
    │ (4 bytes)    │ (1 byte)│ (1)  │ (1 byte) │ (4 bytes)│
    └──────────────┴─────────┴──────┴──────────┴──────────┘

    - MAGIC: 'CSYN' - identifies this as a clipboard sync message
    - VERSION: Protocol version (currently 1)
    - TYPE: Message type (see PacketType)
    - ROOM_LEN: Length of room name in bytes
    - DATA_LEN: Length of data payload in bytes
    """

    # struct format string:
    # ! = network byte order (big-endian)
    # 4s = 4-byte string (magic)
    # B = unsigned byte (version)
    # B = unsigned byte (type)
    # B = unsigned byte (room length)
    # I = unsigned int 4 bytes (data length)
    HEADER_FORMAT = "!4sBBBI"
    HEADER_SIZE = 11
    MAGIC = b'CSYN'  # "Clipboard SYNc"
    VERSION = 1

    @staticmethod
    def pack(room_name: str, data: bytes, packet_type: int = PacketType.DATA) -> bytes:
        """
        Create a complete message packet.

        Args:
            room_name: Name of the room (will be encoded to UTF-8)
            data: Binary payload (encrypted clipboard data, etc.)
            packet_type: Type of message (default: DATA)

        Returns:
            Complete packet: [header][room_name][data]
        """
        # Convert room name to bytes
        room_bytes = room_name.encode('utf-8')
        room_len = len(room_bytes)
        data_len = len(data)

        # Build the header
        header = struct.pack(
            ClipProtocol.HEADER_FORMAT,
            ClipProtocol.MAGIC,
            ClipProtocol.VERSION,
            packet_type,
            room_len,
            data_len
        )

        # Combine header + room name + data
        return header + room_bytes + data

    @staticmethod
    def unpack_header(header_bytes: bytes):
        """
        Parse a message header.

        Args:
            header_bytes: The first 11 bytes of a message

        Returns:
            Tuple of (magic, version, type, room_len, data_len)
        """
        return struct.unpack(ClipProtocol.HEADER_FORMAT, header_bytes)