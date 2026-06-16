import os
import time

from ipv8.keyvault.crypto import default_eccrypto

from common.banner import divider, rows, rule, section

GROUP_BUDGET_SECONDS = 10.0


# in-memory mirror of the lab 2 server state for a single group
class MockServer:
    def __init__(self, member_pubs: list[bytes]) -> None:
        self.member_pubs = member_pubs
        self.group_id = "demo_group_" + os.urandom(4).hex()
        self.round = 0
        self.submitters_seen: set[bytes] = set()
        self.start_time: float | None = None

    # issues a fresh 32-byte nonce and starts the wall-clock budget on round 1
    def challenge(self) -> tuple[bytes, int, float]:
        self.round += 1
        if self.start_time is None:
            self.start_time = time.time()
        nonce = os.urandom(32)
        deadline = self.start_time + GROUP_BUDGET_SECONDS
        return nonce, self.round, deadline

    # validates a 3-signature bundle against the registered member keys
    def submit(
        self, nonce: bytes, round_num: int, sigs: list[bytes], submitter_pub: bytes
    ) -> str:
        if submitter_pub in self.submitters_seen:
            return "rejected: submitter already used in a previous round"
        for i, sig in enumerate(sigs):
            pub = default_eccrypto.key_from_public_bin(self.member_pubs[i])
            if not default_eccrypto.is_valid_signature(pub, nonce, sig):
                return f"rejected: invalid signature from member {i + 1}"
        self.submitters_seen.add(submitter_pub)
        elapsed = time.time() - self.start_time
        return f"round {round_num} recorded at {elapsed:.2f}s of {GROUP_BUDGET_SECONDS:.0f}s"


def main() -> None:
    rule("LAB 2 LOCAL DEMO")
    print("Three in-process signers complete three rounds of round-robin signing.")
    print(
        f"Total budget: {GROUP_BUDGET_SECONDS:.0f}s wall-clock across all three rounds."
    )
    print()

    section("KEY GENERATION")
    keys = [default_eccrypto.generate_key("curve25519") for _ in range(3)]
    pubs = [k.pub().key_to_bin() for k in keys]
    rows(
        [
            ("Member 1 key", f"...{pubs[0][-8:].hex()}"),
            ("Member 2 key", f"...{pubs[1][-8:].hex()}"),
            ("Member 3 key", f"...{pubs[2][-8:].hex()}"),
        ]
    )

    section("REGISTRATION")
    server = MockServer(pubs)
    rows(
        [
            ("Group ID", server.group_id),
            ("Members", 3),
        ]
    )

    for round_num in (1, 2, 3):
        section(f"ROUND {round_num}")
        nonce, issued_round, deadline = server.challenge()
        assert issued_round == round_num
        print(f"[server] issued nonce={nonce[:8].hex()}... round={issued_round}")

        submitter_index = round_num  # round N submitted by member N
        sigs = [default_eccrypto.create_signature(k, nonce) for k in keys]
        print(
            f"[member {submitter_index}] collected three signatures, submitting bundle"
        )

        result = server.submit(nonce, round_num, sigs, pubs[submitter_index - 1])
        print(f"[server] {result}")

    elapsed = time.time() - server.start_time
    divider()
    rows(
        [
            ("Rounds completed", "3/3"),
            ("Distinct submitters", len(server.submitters_seen)),
            ("Elapsed", f"{elapsed:.2f}s"),
            ("Budget", f"{GROUP_BUDGET_SECONDS:.2f}s"),
            ("Within budget", elapsed < GROUP_BUDGET_SECONDS),
        ]
    )
    assert len(server.submitters_seen) == 3 and elapsed < GROUP_BUDGET_SECONDS
    rule("LAB 2 DEMO PASSED")


if __name__ == "__main__":
    main()
