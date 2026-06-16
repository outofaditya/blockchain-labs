import time
from struct import Struct
from hashlib import sha256

from labs.one.miner import EMAIL, PREFIX, GITHUB_URL, validate_nonce
from common.banner import rule, rows, divider, section

# difficulty lowered from the spec so the demo finishes in roughly a second
DEMO_DIFFICULTY = 20
_NONCE_STRUCT = Struct(">q")


# searches the nonce space single threaded until a digest satisfies the bit target
def search(difficulty: int) -> tuple[int, bytes, int]:
    # seed sha256 with the static prefix so only nonce bytes change per attempt
    base = sha256(PREFIX)
    nonce = 0
    while True:
        # clone the cached state and mix in the candidate nonce
        h = base.copy()
        h.update(_NONCE_STRUCT.pack(nonce))
        digest = h.digest()
        # stop the moment the digest hits the leading zero target
        if validate_nonce(digest, difficulty):
            return nonce, digest, nonce + 1
        nonce += 1


# walks through hash inputs mining and verification step by step
def main() -> None:
    rule("Lab 1 Local Demo")
    print(
        f"Proof-Of-Work Search At Difficulty {DEMO_DIFFICULTY} Bits "
        f"(Spec Is 28; Lowered For Demo Cadence)."
    )
    print()
    # show the hash preimage so the operator can read every field that gets hashed
    section("Hash Input")
    rows(
        [
            ("Email", EMAIL),
            ("GitHub URL", GITHUB_URL),
            ("Prefix Bytes", f"{PREFIX!r}"),
        ]
    )

    # run the search and report the winner along with the attempt budget used
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

    # recompute the digest from scratch to prove the mined nonce verifies
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
