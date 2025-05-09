import os
import base64
import hashlib
import hmac

BLOCK_SIZE = 16

def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def encrypt_secret(plain_text: str, key: str) -> str:
    key_bytes = hashlib.sha256(key.encode()).digest()
    iv = os.urandom(BLOCK_SIZE)
    data = pad(plain_text.encode())

    # XOR-based AES
    encrypted = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        xor_block = bytes(a ^ b for a, b in zip(block, prev))
        cipher_block = bytes(a ^ b for a, b in zip(xor_block, key_bytes[:BLOCK_SIZE]))  # 1-round
        encrypted.extend(cipher_block)
        prev = cipher_block

    mac = hmac.new(key_bytes, iv + encrypted, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(iv + encrypted + mac).decode()

def decrypt_secret(cipher_text: str, key: str) -> str:
    key_bytes = hashlib.sha256(key.encode()).digest()
    decoded = base64.urlsafe_b64decode(cipher_text.encode())

    iv = decoded[:BLOCK_SIZE]
    encrypted = decoded[BLOCK_SIZE:-32]
    mac = decoded[-32:]

    if not hmac.compare_digest(mac, hmac.new(key_bytes, iv + encrypted, hashlib.sha256).digest()):
        raise ValueError("HMAC verification failed")

    decrypted = bytearray()
    prev = iv
    for i in range(0, len(encrypted), BLOCK_SIZE):
        block = encrypted[i:i+BLOCK_SIZE]
        xor_block = bytes(a ^ b for a, b in zip(block, key_bytes[:BLOCK_SIZE]))
        plain_block = bytes(a ^ b for a, b in zip(xor_block, prev))
        decrypted.extend(plain_block)
        prev = block

    return unpad(decrypted).decode()