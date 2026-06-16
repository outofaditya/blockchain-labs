from hashlib import sha256

from labs.one.miner import DIFFICULTY, EMAIL, GITHUB_URL, PREFIX, validate_nonce, worker


def test_prefix_construction():
    expected = EMAIL.encode() + b"\n" + GITHUB_URL.encode() + b"\n"
    assert PREFIX == expected


def test_difficulty_matches_spec():
    assert DIFFICULTY == 28


def test_validate_nonce_byte_boundary():
    assert validate_nonce(b"\x00\x00\xff" + b"\x00" * 29, 16)
    assert not validate_nonce(b"\x00\x00\xff" + b"\x00" * 29, 17)
    assert validate_nonce(b"\x00\x0f" + b"\x00" * 30, 12)
    assert not validate_nonce(b"\x00\x10" + b"\x00" * 30, 12)


def test_validate_nonce_full_zero_passes_any_difficulty():
    assert validate_nonce(b"\x00" * 32, 256)


def test_worker_terminates_when_stop_event_fires_before_finding():
    from multiprocessing import Event, Queue

    queue = Queue()
    stop = Event()
    stop.set()  # already set so worker exits at first stride check
    # difficulty so high no nonce in the first stride window will pass
    # worker checks stop_event every 16384 nonces, so this terminates within ~ms
    worker(0, 1, queue, stop)
    assert queue.empty()


def test_known_nonce_satisfies_low_difficulty():
    # difficulty 8 = first byte zero. Easy to find by linear search.
    for nonce in range(1024):
        h = sha256(PREFIX)
        h.update(nonce.to_bytes(8, "big", signed=True))
        if validate_nonce(h.digest(), 8):
            return
    raise AssertionError("Expected a difficulty-8 nonce within 1024 attempts")
