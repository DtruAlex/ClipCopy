#!/usr/bin/env python3
"""
Test room authentication - verify wrong passwords are rejected
"""
import sys
import time
import socket
import threading
import hashlib
import hmac
from ClipHub import ClipHub
from ClipProtocol import ClipProtocol, PacketType
from utils import SecurityEngine

print("=" * 70)
print("ROOM AUTHENTICATION TEST")
print("=" * 70)
print()

# Start hub in background
print("[Setup] Starting ClipHub on port 29999...")
hub = ClipHub(host='127.0.0.1', port=29999)
hub_thread = threading.Thread(target=hub.run, daemon=True)
hub_thread.start()
time.sleep(0.5)

def recv_all(sock, n):
    """Receive exactly n bytes"""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def sign_challenge(challenge, password):
    """Sign challenge with password (same as agent does)"""
    key_hash = hashlib.sha256(password.encode()).digest()
    return hmac.new(key_hash, challenge, hashlib.sha256).digest()

# Test 1: First client with correct password
print("\n[Test 1] First client joins with password 'secret123'...")
try:
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock1.settimeout(5)
    sock1.connect(('127.0.0.1', 29999))

    # Send JOIN request
    join_packet = ClipProtocol.pack('test_room', b'', PacketType.JOIN_ROOM)
    sock1.sendall(join_packet)

    # Receive challenge
    header = recv_all(sock1, ClipProtocol.HEADER_SIZE)
    magic, ver, ptype, rlen, dlen = ClipProtocol.unpack_header(header)

    if ptype != PacketType.AUTH_CHALLENGE:
        print(f"❌ Expected AUTH_CHALLENGE, got {ptype}")
        sys.exit(1)

    room_bytes = recv_all(sock1, rlen)
    challenge = recv_all(sock1, dlen)
    print(f"   Received challenge ({len(challenge)} bytes)")

    # Sign challenge
    response = sign_challenge(challenge, "secret123")
    response_packet = ClipProtocol.pack('test_room', response, PacketType.AUTH_RESPONSE)
    sock1.sendall(response_packet)

    # Receive success
    header = recv_all(sock1, ClipProtocol.HEADER_SIZE)
    magic, ver, ptype, rlen, dlen = ClipProtocol.unpack_header(header)

    if ptype != PacketType.AUTH_SUCCESS:
        print(f"❌ Expected AUTH_SUCCESS, got {ptype}")
        sys.exit(1)

    print("✅ First client authenticated successfully")

except Exception as e:
    print(f"❌ Test 1 failed: {e}")
    sys.exit(1)

# Test 2: Second client with CORRECT password
print("\n[Test 2] Second client joins with SAME password 'secret123'...")
try:
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.settimeout(5)
    sock2.connect(('127.0.0.1', 29999))

    # Send JOIN request
    join_packet = ClipProtocol.pack('test_room', b'', PacketType.JOIN_ROOM)
    sock2.sendall(join_packet)

    # Receive challenge
    header = recv_all(sock2, ClipProtocol.HEADER_SIZE)
    magic, ver, ptype, rlen, dlen = ClipProtocol.unpack_header(header)
    room_bytes = recv_all(sock2, rlen)
    challenge = recv_all(sock2, dlen)

    # Sign challenge with CORRECT password
    response = sign_challenge(challenge, "secret123")
    response_packet = ClipProtocol.pack('test_room', response, PacketType.AUTH_RESPONSE)
    sock2.sendall(response_packet)

    # Should receive success
    header = recv_all(sock2, ClipProtocol.HEADER_SIZE)
    magic, ver, ptype, rlen, dlen = ClipProtocol.unpack_header(header)

    if ptype == PacketType.AUTH_SUCCESS:
        print("✅ Second client authenticated successfully (correct password)")
    else:
        print(f"❌ Expected AUTH_SUCCESS, got {ptype}")
        sys.exit(1)

except Exception as e:
    print(f"❌ Test 2 failed: {e}")
    sys.exit(1)

# Test 3: Third client with WRONG password
print("\n[Test 3] Third client tries to join with WRONG password 'wrongpass'...")
try:
    sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock3.settimeout(5)
    sock3.connect(('127.0.0.1', 29999))

    # Send JOIN request
    join_packet = ClipProtocol.pack('test_room', b'', PacketType.JOIN_ROOM)
    sock3.sendall(join_packet)

    # Receive challenge
    header = recv_all(sock3, ClipProtocol.HEADER_SIZE)
    magic, ver, ptype, rlen, dlen = ClipProtocol.unpack_header(header)
    room_bytes = recv_all(sock3, rlen)
    challenge = recv_all(sock3, dlen)

    # Sign challenge with WRONG password
    response = sign_challenge(challenge, "wrongpass")
    response_packet = ClipProtocol.pack('test_room', response, PacketType.AUTH_RESPONSE)
    sock3.sendall(response_packet)

    # Should receive failure
    header = recv_all(sock3, ClipProtocol.HEADER_SIZE)
    magic, ver, ptype, rlen, dlen = ClipProtocol.unpack_header(header)

    if ptype == PacketType.AUTH_FAILURE:
        print("✅ Third client correctly REJECTED (wrong password)")
    else:
        print(f"❌ Expected AUTH_FAILURE, got {ptype}")
        print("❌ SECURITY BREACH: Wrong password was accepted!")
        sys.exit(1)

except Exception as e:
    print(f"❌ Test 3 failed: {e}")
    sys.exit(1)

# Cleanup
sock1.close()
sock2.close()
sock3.close()

print("\n" + "=" * 70)
print("TEST SUMMARY")
print("=" * 70)
print("✅ Test 1: First client joins - PASSED")
print("✅ Test 2: Second client with correct password - PASSED")
print("✅ Test 3: Third client with wrong password REJECTED - PASSED")
print()
print("🎉 AUTHENTICATION WORKING CORRECTLY!")
print("🔒 Wrong passwords are now rejected")
print("=" * 70)
