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
            return "Rejected: Submitter Already Used In A Previous Round"
        for i, sig in enumerate(sigs):
            pub = default_eccrypto.key_from_public_bin(self.member_pubs[i])
            if not default_eccrypto.is_valid_signature(pub, nonce, sig):
                return f"Rejected: Invalid Signature From Member {i + 1}"
        self.submitters_seen.add(submitter_pub)
        elapsed = time.time() - self.start_time
        return f"Round {round_num} Recorded At {elapsed:.2f}s Of {GROUP_BUDGET_SECONDS:.0f}s"


def main() -> None:
    rule("Lab 2 Local Demo")
    print("Three In-Process Signers Complete Three Rounds Of Round-Robin Signing.")
    print(
        f"Total Budget: {GROUP_BUDGET_SECONDS:.0f}s Wall-Clock Across All Three Rounds."
    )
    print()

    section("Key Generation")
    keys = [default_eccrypto.generate_key("curve25519") for _ in range(3)]
    pubs = [k.pub().key_to_bin() for k in keys]
    rows(
        [
            ("Member 1 Key", f"...{pubs[0][-8:].hex()}"),
            ("Member 2 Key", f"...{pubs[1][-8:].hex()}"),
            ("Member 3 Key", f"...{pubs[2][-8:].hex()}"),
        ]
    )

    section("Registration")
    server = MockServer(pubs)
    rows(
        [
            ("Group ID", server.group_id),
            ("Members", 3),
        ]
    )

    for round_num in (1, 2, 3):
        section(f"Round {round_num}")
        nonce, issued_round, _deadline = server.challenge()
        assert issued_round == round_num
        print(f"[Server] Issued Nonce={nonce[:8].hex()}... Round={issued_round}")

        submitter_index = round_num  # round N submitted by member N
        sigs = [default_eccrypto.create_signature(k, nonce) for k in keys]
        print(
            f"[Member {submitter_index}] Collected Three Signatures, Submitting Bundle"
        )

        result = server.submit(nonce, round_num, sigs, pubs[submitter_index - 1])
        print(f"[Server] {result}")

    elapsed = time.time() - server.start_time
    divider()
    rows(
        [
            ("Rounds Completed", "3/3"),
            ("Submitters", len(server.submitters_seen)),
            ("Elapsed", f"{elapsed:.2f}s"),
            ("Budget", f"{GROUP_BUDGET_SECONDS:.2f}s"),
            ("Within Budget", elapsed < GROUP_BUDGET_SECONDS),
        ]
    )
    assert len(server.submitters_seen) == 3 and elapsed < GROUP_BUDGET_SECONDS
    rule("Lab 2 Demo Passed")


if __name__ == "__main__":
    main()
