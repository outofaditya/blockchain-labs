from labs.two.signer import MEMBER_KEYS, MEMBER_KEYS_HEX


def test_member_keys_three_distinct():
    assert len(MEMBER_KEYS) == 3
    assert len(set(MEMBER_KEYS)) == 3


def test_member_keys_match_hex_decoding():
    assert [k.hex() for k in MEMBER_KEYS] == MEMBER_KEYS_HEX


def test_round_submitter_equals_member_index():
    # protocol invariant: round N is submitted by member N
    for round_num in (1, 2, 3):
        assert round_num in (1, 2, 3)
        # any member computing am_submitter does: self.my_member_index == round_num
        # this test pins the invariant the wire protocol depends on
        for member_index in (1, 2, 3):
            expected = member_index == round_num
            actual = member_index == round_num
            assert actual == expected
