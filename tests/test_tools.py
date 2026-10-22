"""Tests for the MCP tool layer — the remote server and the stdio server.

Both transports are thin wrappers over `vault_core` plus `credtypes`; the
regression that motivated the stdio rewrite was that its `vault_save` called
`save_credential` with the wrong signature, so every save raised. These tests
call the tool functions directly against a private vault.

Sample values are RFC 5737 documentation addresses / made-up strings.
"""

import json

import pytest


def _ssh_record():
    return {"host": "192.0.2.10", "port": "2222", "username": "demo",
            "password": "sample-password"}


# ---------------------------------------------------------------------------
# Remote server tool layer
# ---------------------------------------------------------------------------
def test_save_roundtrip_and_field_reads(server):
    out = server.vault_save(name="demo-ssh", type="ssh", fields=_ssh_record())
    assert out.startswith("Saved credential 'demo-ssh' (type=ssh)")
    assert "Incomplete" not in out

    assert server.vault_get(name="demo-ssh", field="host") == "192.0.2.10"
    assert server.vault_get(name="demo-ssh", field="port") == "2222"
    assert server.vault_get(name="demo-ssh", field="username") == "demo"
    assert server.vault_get(name="demo-ssh", field="password") == "sample-password"


def test_vault_get_without_field_keeps_returning_the_primary_secret(server):
    server.vault_save(name="demo-ssh", type="ssh", fields=_ssh_record())
    assert server.vault_get(name="demo-ssh") == "sample-password"

    server.vault_save(name="demo-generic", value="raw-secret", note="n")
    assert server.vault_get(name="demo-generic") == "raw-secret"


def test_vault_get_unknown_field_is_loud(server):
    server.vault_save(name="demo-ssh", type="ssh", fields=_ssh_record())
    out = server.vault_get(name="demo-ssh", field="nope")
    assert out.startswith("ERROR:")
    assert "host" in out and "port" in out      # names what does exist


def test_vault_get_unknown_record_is_loud(server):
    assert server.vault_get(name="missing").startswith("ERROR:")


def test_describe_masks_secrets_but_shows_the_rest(server):
    server.vault_save(name="demo-ssh", type="ssh", fields=_ssh_record())
    d = json.loads(server.vault_describe(name="demo-ssh"))
    assert d["type"] == "ssh"
    assert d["complete"] is True
    assert d["missing"] == []
    assert d["fields"]["host"]["value"] == "192.0.2.10"
    assert d["fields"]["password"]["length"] == len("sample-password")
    assert "value" not in d["fields"]["password"]
    assert "sample-password" not in server.vault_describe(name="demo-ssh")


def test_list_reports_fields_and_completeness(server):
    server.vault_save(name="full", type="ssh", fields=_ssh_record())
    server.vault_save(name="partial", type="ssh", fields={"host": "192.0.2.11"})
    items = {i["name"]: i for i in json.loads(server.vault_list())}

    assert set(items["full"]["fields"]) == {"host", "port", "username", "password"}
    assert items["full"]["complete"] is True
    assert items["partial"]["complete"] is False
    assert "port" in items["partial"]["missing"]
    assert "sample-password" not in server.vault_list()


@pytest.mark.parametrize("kwargs,needle", [
    (dict(name="bad-type", type="bogus", fields={"host": "192.0.2.10"}),
     "unknown credential type"),
    (dict(name="bad-field", type="ssh", fields={"ip": "192.0.2.10"}),
     "unknown field"),
    (dict(name="no-host", type="ssh", fields={"port": "22"}),
     "missing required field"),
])
def test_save_rejects_bad_shapes_and_stores_nothing(server, kwargs, needle):
    out = server.vault_save(**kwargs)
    assert out.startswith("ERROR:")
    assert needle in out
    assert json.loads(server.vault_list()) == []


def test_save_warns_about_a_still_incomplete_record(server):
    out = server.vault_save(name="partial", type="ssh", fields={"host": "192.0.2.11"})
    assert out.startswith("Saved credential")
    assert "Incomplete: missing" in out


def test_delete(server):
    server.vault_save(name="demo", type="ssh", fields=_ssh_record())
    assert server.vault_delete(name="demo").startswith("Deleted")
    assert server.vault_delete(name="demo").startswith("ERROR:")
    assert json.loads(server.vault_list()) == []


def test_tools_refuse_to_run_without_a_namespace(server):
    token = server.auth_user_ctx.set(None)
    try:
        assert server.vault_list() == "ERROR: unauthorized"
        assert server.vault_get(name="x") == "ERROR: unauthorized"
    finally:
        server.auth_user_ctx.reset(token)


# ---------------------------------------------------------------------------
# stdio tool layer — this is where the signature bug lived
# ---------------------------------------------------------------------------
def test_stdio_save_no_longer_raises(stdio):
    out = stdio.vault_save(name="demo-ssh", type="ssh", fields=_ssh_record())
    assert out.startswith("Saved credential 'demo-ssh'")
    assert "ERROR" not in out


def test_stdio_field_reads(stdio):
    stdio.vault_save(name="demo-ssh", type="ssh", fields=_ssh_record())
    assert stdio.vault_get(name="demo-ssh", field="host") == "192.0.2.10"
    assert stdio.vault_get(name="demo-ssh") == "sample-password"
    assert stdio.vault_get(name="demo-ssh", field="nope").startswith("ERROR:")


def test_stdio_describe_and_list(stdio):
    stdio.vault_save(name="demo-ssh", type="ssh", fields=_ssh_record())
    d = json.loads(stdio.vault_describe(name="demo-ssh"))
    assert d["complete"] is True
    assert "value" not in d["fields"]["password"]
    assert json.loads(stdio.vault_list())[0]["complete"] is True


def test_stdio_save_validation(stdio):
    assert stdio.vault_save(name="x", type="bogus", fields={}).startswith("ERROR:")
    assert stdio.vault_save(name="x", type="ssh", fields={"ip": "1.2.3.4"}).startswith("ERROR:")
    assert json.loads(stdio.vault_list()) == []


def test_stdio_and_remote_share_one_store(server, stdio):
    """A credential saved over one transport is readable over the other."""
    server.vault_save(name="shared", type="ssh", fields=_ssh_record())
    assert stdio.vault_get(name="shared", field="host") == "192.0.2.10"

    stdio.vault_save(name="shared-2", value="second-secret")
    assert server.vault_get(name="shared-2") == "second-secret"
