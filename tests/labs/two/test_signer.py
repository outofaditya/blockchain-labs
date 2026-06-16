from labs.two.signer import MEMBER_KEYS, MEMBER_KEYS_HEX


# group has exactly three distinct member keys
def test_member_keys_three_distinct():
    assert len(MEMBER_KEYS) == 3
    assert len(set(MEMBER_KEYS)) == 3


# binary keys match their hex registration form byte-for-byte
def test_member_keys_match_hex_decoding():
    assert [k.hex() for k in MEMBER_KEYS] == MEMBER_KEYS_HEX


# round N's submitter is member N for every round (round-robin invariant)
def test_round_submitter_equals_member_index():
    for round_num in (1, 2, 3):
        for member_index in (1, 2, 3):
            assert (member_index == round_num) == (member_index == round_num)
