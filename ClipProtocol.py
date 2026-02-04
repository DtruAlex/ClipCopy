import struct


class PacketType:
    """Packet type constants for multi-room clipboard protocol"""
    DATA = 0x01              # Clipboard data (text only, legacy)
    HANDSHAKE = 0x02         # Connection handshake
    JOIN_ROOM = 0x05         # Join a room
    LEAVE_ROOM = 0x06        # Leave a room
    CLIPBOARD_FORMATS = 0x08 # Rich clipboard (multiple formats)
    AUTH_CHALLENGE = 0x09    # Hub sends challenge for authentication
    AUTH_RESPONSE = 0x0A     # Client sends signed response
    AUTH_SUCCESS = 0x0B      # Hub confirms authentication success
    AUTH_FAILURE = 0x0C      # Hub rejects authentication


class ClipProtocol:
    """
    Binary protocol for multi-room clipboard synchronization.

    Header Format (11 bytes):
    - MAGIC: 4 bytes ('CSYN')
    - VERSION: 1 byte
    - TYPE: 1 byte (see PacketType)
    - ROOMLEN: 1 byte
    - DATALEN: 4 bytes
    """
    HEADER_FORMAT = "!4sBBBI"
    HEADER_SIZE = 11
    MAGIC = b'CSYN'
    VERSION = 1

    @staticmethod
    def pack(room_name: str, data: bytes, p_type: int = PacketType.DATA) -> bytes:
        """Pack room name and data into protocol packet"""
        room_bytes = room_name.encode('utf-8')
        room_len = len(room_bytes)
        data_len = len(data)

        header = struct.pack(
            ClipProtocol.HEADER_FORMAT,
            ClipProtocol.MAGIC,
            ClipProtocol.VERSION,
            p_type,
            room_len,
            data_len
        )
        return header + room_bytes + data

    @staticmethod
    def unpack_header(header_bytes: bytes):
        """Unpack header tuple: (magic, version, type, room_len, data_len)"""
        return struct.unpack(ClipProtocol.HEADER_FORMAT, header_bytes)