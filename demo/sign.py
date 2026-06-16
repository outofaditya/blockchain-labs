import os
import time

from ipv8.keyvault.crypto import default_eccrypto

from common.banner import rule, rows, divider, section

# total wall clock budget the real lab 2 server enforces across three rounds
GROUP_BUDGET_SECONDS = 10.0


# in memory mirror of the lab 2 server state for a single group
class MockServer:
    def __init__(self, member_pubs: list[bytes]) -> None:
        self.member_pubs = member_pubs
        self.group_id = "demo_group_" + os.urandom(4).hex()
        self.round = 0
        self.submitters_seen: set[bytes] = set()
        self.start_time: float | None = None

    # issues a fresh 32 byte nonce and starts the wall clock budget on round 1
    def challenge(self) -> tuple[bytes, int, float]:
        # advance to the next round number
        self.round += 1
        # start the budget clock on the very first challenge
        if self.start_time is None:
            self.start_time = time.time()
        # pick a fresh nonce and report the budget deadline back to the caller
        nonce = os.urandom(32)
        deadline = self.start_time + GROUP_BUDGET_SECONDS
        return nonce, self.round, deadline

    # validates a three signature bundle against the registered member keys
    def submit(
        self, nonce: bytes, round_num: int, sigs: list[bytes], submitter_pub: bytes
    ) -> str:
        # refuse a submitter that already drove an earlier round
        if submitter_pub in self.submitters_seen:
            return "Rejected: Submitter Already Used In A Previous Round"
        # verify every signature against its registered member key
        for i, sig in enumerate(sigs):
            pub = default_eccrypto.key_from_public_bin(self.member_pubs[i])
            if not default_eccrypto.is_valid_signature(pub, nonce, sig):
                return f"Rejected: Invalid Signature From Member {i + 1}"
        # record the submitter and report the elapsed time against the budget
        self.submitters_seen.add(submitter_pub)
        elapsed = time.time() - self.start_time
        return (
            f"Round {round_num} Recorded At {elapsed:.2f}s "
            f"Of {GROUP_BUDGET_SECONDS:.0f}s"
        )


# runs the three round signing demo against a fresh mock server instance
def main() -> None:
    rule("Lab 2 Local Demo")
    print("Three In-Process Signers Complete Three Rounds Of Round-Robin Signing.")
    print(
        f"Total Budget: {GROUP_BUDGET_SECONDS:.0f}s Wall-Clock Across All Three Rounds."
    )
    print()

    # spawn three fresh ipv8 keypairs to act as the three group members
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

    # build the mock server and print the group identity for clarity
    section("Registration")
    server = MockServer(pubs)
    rows(
        [
            ("Group ID", server.group_id),
            ("Members", 3),
        ]
    )

    # walk the three rounds end to end with the canonical round robin submitter slot
    for round_num in (1, 2, 3):
        section(f"Round {round_num}")
        nonce, issued_round, _deadline = server.challenge()
        assert issued_round == round_num
        print(f"[Server] Issued Nonce={nonce[:8].hex()}... Round={issued_round}")

        # round N is submitted by member N so the index follows the round number
        submitter_index = round_num
        sigs = [default_eccrypto.create_signature(k, nonce) for k in keys]
        print(
            f"[Member {submitter_index}] Collected Three Signatures, Submitting Bundle"
        )

        result = server.submit(nonce, round_num, sigs, pubs[submitter_index - 1])
        print(f"[Server] {result}")

    # report the final tally and assert the demo stayed inside the budget
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
