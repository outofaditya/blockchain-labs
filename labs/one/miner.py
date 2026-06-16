import os
import time
from struct import Struct
from hashlib import sha256
from multiprocessing import Event, Queue, Process

from common.banner import rule, section, rows

DIFFICULTY = 28
EMAIL = "acpatil@tudelft.nl"
GITHUB_URL = "https://github.com/outofaditya/blockchain-labs"
PREFIX = EMAIL.encode() + b"\n" + GITHUB_URL.encode() + b"\n"

# precompiled for the mining hot path
_NONCE_STRUCT = Struct(">q")


# checks leading zeros byte by byte to short circuit cheaply
def validate_nonce(digest: bytes, bits: int) -> bool:
    full, rem = divmod(bits, 8)
    if any(digest[:full]):
        return False
    return not rem or digest[full] < (1 << (8 - rem))


# each subprocess mines its own nonce stride so the search partitions without coordination
def worker(worker_id: int, num_workers: int, result_queue, stop_event):
    base = sha256(PREFIX)
    nonce = worker_id
    while True:
        h = base.copy()
        h.update(_NONCE_STRUCT.pack(nonce))
        digest = h.digest()
        if validate_nonce(digest, DIFFICULTY):
            result_queue.put((nonce, digest))
            stop_event.set()
            return
        nonce += num_workers
        # cheap power of 2 check fires every 16384 iterations
        if nonce & 0x3FFF == 0 and stop_event.is_set():
            return


# spawns one worker per core and returns as soon as any worker finds a valid nonce
def mine():
    num_workers = os.cpu_count() or 1
    rule("PROOF-OF-WORK MINER PROGRAM")
    rows(
        [
            ("Email", EMAIL),
            ("GitHub URL", GITHUB_URL),
            ("Workers", num_workers),
            ("Difficulty", f"{DIFFICULTY} Leading Zero Bits"),
        ]
    )
    section("MINING STARTED")

    result_queue, stop_event = Queue(), Event()
    workers = [
        Process(target=worker, args=(i, num_workers, result_queue, stop_event))
        for i in range(num_workers)
    ]
    start = time.time()
    for w in workers:
        w.start()

    nonce, digest = result_queue.get()
    elapsed = time.time() - start

    rows(
        [
            ("Nonce", nonce),
            ("Digest Value", digest.hex()),
            ("Time Elapsed", f"{elapsed:.2f} seconds"),
        ]
    )
    rule()

    for w in workers:
        w.terminate()
    for w in workers:
        w.join()

    return nonce, digest


if __name__ == "__main__":
    mine()
