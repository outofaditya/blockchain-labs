import os
import time
import struct
import hashlib
import multiprocessing as mp

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


# the worker function
def worker(worker_id: int, num_workers: int, result_queue, stop_event):
    base = hashlib.sha256(prefix)

    # partition the nonce range as i then i+N and so on
    nonce = worker_id

    while not stop_event.is_set():
        h = base.copy()
        h.update(struct.pack(">q", nonce))
        digest = h.digest()
        if validate_nonce(digest, DIFFICULTY):
            # push the result to queue and set the stop event
            result_queue.put((nonce, digest))
            stop_event.set()
            return
        nonce += num_workers


# the mining loop
def mine():
    # get the available core count
    num_workers = os.cpu_count() or 1

    # general print statements
    print(f"Email: {EMAIL}")
    print(f"GitHub URL: {GITHUB_URL}")
    print(f"Number of Workers: {num_workers}")
    print(f"Difficulty Level: {DIFFICULTY} Leading Zero Bits\n")

    # set the structures for workers
    result_queue = mp.Queue()
    stop_event = mp.Event()
    start = time.time()

    workers = [
        mp.Process(target=worker, args=(i, num_workers, result_queue, stop_event))
        for i in range(num_workers)
    ]

    # start the worker processes
    for w in workers:
        w.start()

    # wait for the first result
    nonce, digest = result_queue.get()
    for w in workers:
        w.join()

    elapsed = time.time() - start
    print(f"\nNonce: {nonce}")
    print(f"\nHash Value: {digest.hex()}")
    print(f"Time Taken: {elapsed:.1f}s")

    return nonce, digest


if __name__ == "__main__":
    mine()
