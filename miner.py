import time
import struct
import hashlib

DIFFICULTY = 28
EMAIL = "acpatil@tudelft.nl"
GITHUB_URL = "https://github.com/outofaditya/blockchain-labs"

prefix = EMAIL.encode("utf-8") + b"\n" + GITHUB_URL.encode("utf-8") + b"\n"


def check_difficulty(digest: bytes, bits: int) -> bool:
    full_bytes, remainder = divmod(bits, 8)
    for b in digest[:full_bytes]:
        if b != 0:
            return False
    if remainder:
        return digest[full_bytes] < (1 << (8 - remainder))
    return True


def mine():
    print(f"Email: {EMAIL}")
    print(f"GitHub URL: {GITHUB_URL}")
    print(f"Difficulty: {DIFFICULTY} Leading Zero Bits\n")

    nonce = 0
    start = time.time()

    while True:
        data = prefix + struct.pack(">q", nonce)
        digest = hashlib.sha256(data).digest()

        if check_difficulty(digest, DIFFICULTY):
            elapsed = time.time() - start
            print(f"\nNonce: {nonce}")
            print(f"Hash: {digest.hex()}")
            print(f"Attempts: {nonce + 1:,}")
            print(f"Time: {elapsed:.1f}s")
            return nonce, digest

        if nonce % 500_000 == 0 and nonce > 0:
            elapsed = time.time() - start
            rate = nonce / elapsed / 1_000_000
            print(
                f"Nonces Tried: {nonce:>12,} | {rate:.2f}M/s | {elapsed:.0f}s Elapsed"
            )
        nonce += 1


if __name__ == "__main__":
    mine()
