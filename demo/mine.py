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
    rule("Lab 1 Local Demo")
    print(
        f"Proof-Of-Work Search At Difficulty {DEMO_DIFFICULTY} Bits "
        f"(Spec Is 28; Lowered For Demo Cadence)."
    )
    print()
    section("Hash Input")
    rows(
        [
            ("Email", EMAIL),
            ("GitHub URL", GITHUB_URL),
            ("Prefix Bytes", f"{PREFIX!r}"),
        ]
    )

    section("Mining")
    start = time.time()
    nonce, digest, attempts = search(DEMO_DIFFICULTY)
    elapsed = time.time() - start
    rows(
        [
            ("Nonce Found", nonce),
            ("Digest", digest.hex()),
            ("Attempts", attempts),
            ("Time Elapsed", f"{elapsed:.2f}s"),
        ]
    )

    section("Verification")
    h = sha256(PREFIX)
    h.update(_NONCE_STRUCT.pack(nonce))
    recomputed = h.digest()
    rows(
        [
            ("Recomputed Hash", recomputed.hex()),
            ("Matches Mined", recomputed == digest),
            ("Zero Bits Pass", validate_nonce(recomputed, DEMO_DIFFICULTY)),
        ]
    )
    divider()
    assert recomputed == digest and validate_nonce(recomputed, DEMO_DIFFICULTY)
    rule("Lab 1 Demo Passed")


if __name__ == "__main__":
    main()
