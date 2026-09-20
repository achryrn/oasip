from oasip.modules.identity_module import (
    generate_permutations,
    infer_email_format,
)


def test_infer_first_last():
    emails = ["john.doe@example.com", "jane.smith@example.com", "bob.jones@example.com"]
    assert infer_email_format(emails) == "first.last"


def test_permutations_include_common():
    perms = generate_permutations("Jane Smith", "example.com", "first.last")
    assert "jane.smith@example.com" in perms
    assert "jsmith@example.com" in perms


def test_permutations_empty_for_one_word():
    assert generate_permutations("solo", "example.com", "first.last") == []
