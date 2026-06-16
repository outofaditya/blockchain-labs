import time
from hashlib import sha256
from struct import Struct

from common.banner import divider, rows, rule, section
from labs.one.miner import EMAIL, GITHUB_URL, PREFIX, validate_nonce

DEMO_DIFFICULTY = 20
_NONCE_STRUCT = Struct(">q")


# searches the nonce space single-threaded until a digest satisfies the bit target
def search(difficulty: int) -> tuple[int, bytes, int]:
    base = sha256(PREFIX)
    nonce = 0
    while True:
        h = base.copy()
        h.update(_NONCE_STRUCT.pack(nonce))
        digest = h.digest()
        if validate_nonce(digest, difficulty):
            return nonce, digest, nonce + 1
        nonce += 1


def main() -> None:
    rule("LAB 1 LOCAL DEMO")
    print(
        f"Mining a proof-of-work nonce at difficulty {DEMO_DIFFICULTY} bits "
        f"(spec is 28 bits, lowered here for demo cadence)."
    )
    print()
    section("HASH INPUT")
    rows(
        [
            ("Email", EMAIL),
            ("GitHub URL", GITHUB_URL),
            ("Prefix bytes", f"{PREFIX!r}"),
        ]
    )

    section("MINING")
    start = time.time()
    nonce, digest, attempts = search(DEMO_DIFFICULTY)
    elapsed = time.time() - start
    rows(
        [
            ("Nonce found", nonce),
            ("Digest", digest.hex()),
            ("Attempts", attempts),
            ("Time", f"{elapsed:.2f}s"),
        ]
    )

    section("VERIFICATION")
    h = sha256(PREFIX)
    h.update(_NONCE_STRUCT.pack(nonce))
    recomputed = h.digest()
    rows(
        [
            ("Recomputed digest", recomputed.hex()),
            ("Matches mined digest", recomputed == digest),
            ("Has required zero bits", validate_nonce(recomputed, DEMO_DIFFICULTY)),
        ]
    )
    divider()
    assert recomputed == digest and validate_nonce(recomputed, DEMO_DIFFICULTY)
    rule("LAB 1 DEMO PASSED")


if __name__ == "__main__":
    main()
