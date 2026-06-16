import os
import time
from struct import Struct
from hashlib import sha256
from multiprocessing import Event, Queue, Process

from common.banner import rule, rows, section

DIFFICULTY = 28
EMAIL = "acpatil@tudelft.nl"
GITHUB_URL = "https://github.com/outofaditya/blockchain-labs"
PREFIX = EMAIL.encode() + b"\n" + GITHUB_URL.encode() + b"\n"

# precompiled struct used to pack the 8 byte nonce field inside the hot loop
_NONCE_STRUCT = Struct(">q")


# checks leading zero bits one byte at a time so the loop can short circuit cheaply
def validate_nonce(digest: bytes, bits: int) -> bool:
    full, rem = divmod(bits, 8)
    if any(digest[:full]):
        return False
    return not rem or digest[full] < (1 << (8 - rem))


# subprocess body that searches its own nonce stride and signals on success
def worker(worker_id: int, num_workers: int, result_queue, stop_event):
    # seed sha256 with the static prefix so only nonce bytes change per attempt
    base = sha256(PREFIX)
    # each worker starts at its index so the strides never overlap
    nonce = worker_id
    while True:
        # clone the cached prefix state and mix in the current nonce
        h = base.copy()
        h.update(_NONCE_STRUCT.pack(nonce))
        digest = h.digest()
        # winning digest pushes the nonce to the parent and signals siblings to stop
        if validate_nonce(digest, DIFFICULTY):
            result_queue.put((nonce, digest))
            stop_event.set()
            return
        nonce += num_workers
        # cheap power of two check probes the stop event every 16384 attempts
        if nonce & 0x3FFF == 0 and stop_event.is_set():
            return


# launches one worker per core and returns the first valid nonce produced
def mine():
    # one subprocess per core saturates the cpu without overcommitting
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

    # shared queue and stop event coordinate winner detection across workers
    result_queue, stop_event = Queue(), Event()
    # spawn one process per stride
    workers = [
        Process(target=worker, args=(i, num_workers, result_queue, stop_event))
        for i in range(num_workers)
    ]
    start = time.time()
    for w in workers:
        w.start()

    # blocks until any worker pushes a winning nonce
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

    # tear down every worker so the parent process exits cleanly
    for w in workers:
        w.terminate()
    for w in workers:
        w.join()

    return nonce, digest


if __name__ == "__main__":
    mine()
