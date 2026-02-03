def crypt(data: bytes, key: str) -> bytes:
    """
    Symmetric XOR encryption.
    Applying this twice with the same key returns the original data.
    """
    if not key:
        return data
    key_bytes = key.encode('utf-8')
    # Standard library byte-wise XOR
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])