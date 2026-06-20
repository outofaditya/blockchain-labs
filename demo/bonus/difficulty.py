import time

from bonus.difficulty import RETARGET_INTERVAL, TARGET_BLOCK_SECONDS, retarget
from labs.three.chain import mine_block
from common.banner import rule, rows, divider, section

# dummy hashes used as the static portion of the mined header
_ZERO = b"\x00" * 32
# every block prints with this minimum delay so even low difficulty rounds stay readable
_FLOOR_SLEEP = 0.25
# how many blocks each scenario runs for
_BLOCKS = 16


# runs one scenario by mining real blocks while synthesizing the network cadence
def simulate(label, gap_seconds, start_difficulty=18):
    section(label)
    timestamps = [0]
    difficulty = start_difficulty
    snapshots = []
    for h in range(1, _BLOCKS + 1):
        # actually mine a block so the demo time correlates with the current difficulty
        start = time.time()
        mine_block(_ZERO, _ZERO, difficulty, h)
        mining_time = time.time() - start
        # synthesized timestamp drives the retarget regardless of real wall clock
        timestamps.append(timestamps[-1] + gap_seconds)
        print(
            f"  Block {h:>2}  difficulty={difficulty:>2}  "
            f"mined in {mining_time * 1000:>6.0f} ms"
        )
        # difficulty for the next block uses the synthesized timeline
        difficulty = retarget(h, timestamps, difficulty)
        # floor sleep keeps the cadence visible even when mining is cheap
        time.sleep(_FLOOR_SLEEP)
    snapshots.append(("Final Difficulty", difficulty))
    return difficulty


# entry point that walks three contrasting network conditions
def main():
    rule("Bonus Two Adaptive Difficulty")
    print(f"Target Block Time: {TARGET_BLOCK_SECONDS}s")
    print(f"Retarget Interval: {RETARGET_INTERVAL} Blocks")
    print(f"Blocks Per Scenario: {_BLOCKS}")
    print("Start Difficulty:  18 bits")
    print()

    # surge fires when blocks land twice as fast as target
    final_surge = simulate("Scenario A Hash Power Surges", gap_seconds=1)
    print()
    # drought fires when blocks land four times slower than target
    final_drought = simulate("Scenario B Hash Power Drops", gap_seconds=8)
    print()
    # steady fires when network meets the target exactly
    final_steady = simulate("Scenario C Steady State", gap_seconds=TARGET_BLOCK_SECONDS)

    divider()
    rows(
        [
            ("Surge End", final_surge),
            ("Drought End", final_drought),
            ("Steady End", final_steady),
            ("Surge Raised", final_surge > 18),
            ("Drought Dropped", final_drought < 18),
            ("Steady Unchanged", final_steady == 18),
        ]
    )
    assert final_surge > 18 and final_drought < 18 and final_steady == 18
    rule("Bonus Two Demo Passed")


if __name__ == "__main__":
    main()
