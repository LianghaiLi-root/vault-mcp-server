"""Unit tests for the credential type catalog and shape rules.

Pure functions only — no storage, no transport. All sample values are RFC 5737
documentation addresses / made-up strings; nothing here is a real credential.
"""

import pytest

from vault_mcp import credtypes


def test_catalog_covers_every_documented_type():
    assert sorted(credtypes.CRED_TYPES) == ["api", "db", "generic", "ssh", "web"]
    assert credtypes.TYPE_LABELS["ssh"] == "SSH 服务器"


def test_ssh_field_keys_and_secrets():
    assert credtypes.field_keys("ssh") == [
        "host", "port", "username", "password", "private_key"]
    assert credtypes.secret_keys("ssh") == {"password", "private_key"}


def test_type_spec_rejects_unknown_type_and_lists_valid_ones():
    with pytest.raises(ValueError) as ei:
        credtypes.type_spec("bogus")
    msg = str(ei.value)
    assert "unknown credential type 'bogus'" in msg
    for t in ("api", "db", "generic", "ssh", "web"):
        assert t in msg


@pytest.mark.parametrize("value,expected", [
    (None, True), ("", True), ("   ", True), ("x", False), ("  x ", False), (0, False),
])
def test_blank(value, expected):
    assert credtypes.blank(value) is expected


def test_missing_fields_complete_ssh_record():
    fields = {"host": "192.0.2.10", "port": "22", "username": "demo",
              "password": "sample-password"}
    assert credtypes.missing_fields("ssh", fields) == []


def test_missing_fields_reports_gaps():
    missing = credtypes.missing_fields("ssh", {"host": "192.0.2.10"})
    assert set(missing) == {"port", "username", "password|private_key"}


def test_private_key_satisfies_the_auth_slot():
    fields = {"host": "192.0.2.10", "port": "22", "username": "demo",
              "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
    assert "password|private_key" not in credtypes.missing_fields("ssh", fields)


def test_missing_fields_ignores_unknown_types():
    # A legacy record may carry a type this version no longer knows; it must not
    # raise while listing.
    assert credtypes.missing_fields("legacy", {"anything": "x"}) == []


def test_describe_fields_echoes_non_secrets_and_masks_secrets():
    fields = {"host": "192.0.2.10", "port": "22", "password": "sample-password"}
    out = credtypes.describe_fields("ssh", fields)
    assert out["host"] == {"stored": True, "secret": False, "value": "192.0.2.10"}
    assert out["port"]["value"] == "22"
    assert out["password"] == {"stored": True, "secret": True,
                               "length": len("sample-password")}
    assert "value" not in out["password"]


def test_describe_fields_treats_unknown_keys_as_secret():
    # We cannot prove an unrecognised key is safe to echo, so it is masked but
    # still readable through vault_get(name, field=...).
    out = credtypes.describe_fields("ssh", {"host": "192.0.2.10", "custom": "hunter2"})
    assert out["custom"]["secret"] is True
    assert "value" not in out["custom"]


def test_describe_fields_marks_empty_values():
    out = credtypes.describe_fields("ssh", {"host": "", "port": None})
    assert out["host"] == {"stored": False}
    assert out["port"] == {"stored": False}


def test_validate_accepts_a_good_record():
    assert credtypes.validate_fields("ssh", {"host": "192.0.2.10"}) is None
    assert credtypes.validate_fields("generic", {"value": "x"}) is None


def test_validate_rejects_unknown_type():
    msg = credtypes.validate_fields("bogus", {"host": "192.0.2.10"})
    assert "unknown credential type 'bogus'" in msg


def test_validate_rejects_unknown_field_names():
    # "ip" instead of "host" is the exact typo this check exists for.
    msg = credtypes.validate_fields("ssh", {"ip": "192.0.2.10"})
    assert "unknown field(s) ['ip']" in msg
    assert "host" in msg


@pytest.mark.parametrize("type_,fields,missing", [
    ("ssh", {"port": "22"}, "host"),
    ("web", {"username": "demo"}, "url"),
    ("api", {"url": "https://example.com"}, "token"),
    ("generic", {}, "value"),
    ("db", {"port": "5432"}, "host"),
])
def test_validate_requires_the_anchor_field(type_, fields, missing):
    msg = credtypes.validate_fields(type_, fields)
    assert "missing required field(s)" in msg
    assert missing in msg
