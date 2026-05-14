import time
import struct
import hashlib

# constants
DIFFICULTY = 28
EMAIL = "acpatil@tudelft.nl"
GITHUB_URL = "https://github.com/outofaditya/blockchain-labs"

# binary optimization
prefix = EMAIL.encode("utf-8") + b"\n" + GITHUB_URL.encode("utf-8") + b"\n"


# nonce validation function
def validate_nonce(digest: bytes, bits: int) -> bool:
    # perform byte-wise check for the number of leading zeros
    full_bytes, remainder = divmod(bits, 8)
    # check each byte in the digest
    for b in digest[:full_bytes]:
        if b != 0:
            return False
    # check the remaining bits if any
    if remainder:
        return digest[full_bytes] < (1 << (8 - remainder))
    return True


# the mining loop
def mine():
    # base values
    nonce = 0
    start = time.time()
    base = hashlib.sha256(prefix)

    # general print statements
    print(f"Email: {EMAIL}")
    print(f"GitHub URL: {GITHUB_URL}")
    print(f"Difficulty Level: {DIFFICULTY} Leading Zero Bits\n")

    # loop till we find a winning nonce
    while True:
        h = base.copy()
        h.update(struct.pack(">q", nonce))
        digest = h.digest()

        # check validity of the digest
        if validate_nonce(digest, DIFFICULTY):
            elapsed = time.time() - start

            print(f"\nNonce: {nonce}")
            print(f"\nHash Value: {digest.hex()}")
            print(f"Time Taken: {elapsed:.1f}s")

            return nonce, digest

        # print progress every 500,000 nonces
        if nonce % 500_000 == 0 and nonce > 0:
            elapsed = time.time() - start
            rate = nonce / elapsed / 1_000_000
            print(f"{nonce:>12,} Nonces Tried | {rate:.2f}M/s | {elapsed:.0f}s Elapsed")

        # increment the nonce
        nonce += 1


if __name__ == "__main__":
    mine()
