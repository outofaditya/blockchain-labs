import math
from statistics import median

# how often the network targets one block to appear on the wire
TARGET_BLOCK_SECONDS = 2

# blocks per retarget window smaller window reacts faster but oscillates more
RETARGET_INTERVAL = 8

# past block window for the median validation gate
MEDIAN_PAST_WINDOW = 11

# wall clock seconds a block may exceed local now before being rejected
MAX_FUTURE_DRIFT = 60

# clamp on retarget so a single window cannot move difficulty by more than four times either way
MAX_ADJUST_FACTOR = 4

# floor and ceiling on difficulty bits
MIN_DIFFICULTY = 8
MAX_DIFFICULTY = 32


# median of the last window block timestamps used by the validation gate
def median_past_timestamp(timestamps, window=MEDIAN_PAST_WINDOW):
    if not timestamps:
        return 0
    recent = timestamps[-window:]
    return int(median(recent))


# gate keeper that rejects manipulated past timestamps and far future drift
def is_valid_timestamp(candidate, prev_timestamps, now):
    # candidate must strictly exceed the past window median to defeat single miner manipulation
    if prev_timestamps and candidate <= median_past_timestamp(prev_timestamps):
        return False
    # candidate must not jump past the local clock by more than the allowed drift
    if candidate > now + MAX_FUTURE_DRIFT:
        return False
    return True


# computes the difficulty bits for the next block based on the actual block span
def retarget(
    height,
    timestamps,
    current_difficulty,
    target_seconds=TARGET_BLOCK_SECONDS,
    interval=RETARGET_INTERVAL,
):
    # only adjust on retarget boundaries leaving difficulty stable between them
    if height < interval or height % interval != 0:
        return current_difficulty

    # need interval plus one timestamps to measure the elapsed span across the window
    if len(timestamps) < interval + 1:
        return current_difficulty

    # actual elapsed seconds across the full retarget window
    span = max(1, timestamps[-1] - timestamps[-(interval + 1)])
    expected = interval * target_seconds

    # bigger actual span means blocks were slow ratio drops difficulty
    # smaller actual span means blocks were fast ratio raises difficulty
    ratio = expected / span
    ratio = max(1 / MAX_ADJUST_FACTOR, min(MAX_ADJUST_FACTOR, ratio))

    # each difficulty bit doubles required work hence log base two of the ratio
    delta = math.log2(ratio)
    new_difficulty = int(round(current_difficulty + delta))
    return max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, new_difficulty))
