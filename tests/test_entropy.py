from sentinel import shannon_entropy, looks_random


def test_entropy_values():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0
    assert shannon_entropy("") == 0.0


def test_looks_random():
    assert looks_random("a8Fk2Lm9Qp3Xy7Zt1Bv6Nw")      # long, mixed, high entropy
    assert not looks_random("short1")                   # too short
    assert not looks_random("thisisalllowercasewords")  # no digits / low entropy
