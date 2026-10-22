"""Opt-in smoke test against a *live* remote MCP endpoint (streamable HTTP).

Nothing about a deployment is stored in this repository: the endpoint and its
Bearer token come from the environment, and the whole module is skipped unless
both are present.

    MCP_URL=https://your-vault.example.com/mcp MCP_TOKEN=... pytest -m live

The probe writes one throwaway credential with a random name and deletes it
again, so it is safe to run against a real vault — but it does touch it, which
is why it never runs by default.

Excluded from the default run by `addopts = -m "not live"` in pyproject.toml.
"""

import json
import os
import ssl
import urllib.request
import uuid

import pytest

MCP_URL = os.environ.get("MCP_URL", "")
MCP_TOKEN = os.environ.get("MCP_TOKEN", "")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not (MCP_URL and MCP_TOKEN),
                       reason="set MCP_URL and MCP_TOKEN to run live tests"),
]


class RemoteClient:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.session = None
        self._id = 0

    def rpc(self, method, params=None, notify=False):
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:            # notifications must not carry an id
            self._id += 1
            body["id"] = self._id
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(),
                                     method="POST")
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        if self.session:
            req.add_header("Mcp-Session-Id", self.session)
        with urllib.request.urlopen(req, context=ssl.create_default_context(),
                                    timeout=30) as r:
            sid = r.headers.get("mcp-session-id")
            if sid:
                self.session = sid
            raw = r.read().decode()
        if notify:
            return None
        for line in raw.splitlines():
            if line.startswith("data: "):
                raw = line[6:]
                break
        res = json.loads(raw)
        assert "error" not in res, res["error"]
        return res["result"]

    def tool(self, _tool_name, **args):
        return self.rpc("tools/call", {"name": _tool_name,
                                       "arguments": args})["content"][0]["text"]


@pytest.fixture(scope="module")
def remote():
    c = RemoteClient(MCP_URL, MCP_TOKEN)
    c.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "pytest-live", "version": "1.0"}})
    c.rpc("notifications/initialized", notify=True)
    return c


def test_tools_are_exposed(remote):
    tools = {t["name"] for t in remote.rpc("tools/list")["tools"]}
    assert {"vault_save", "vault_get", "vault_describe",
            "vault_list", "vault_delete"} <= tools


def test_field_aware_roundtrip(remote):
    name = "pytest-probe-" + uuid.uuid4().hex[:8]
    fields = {"host": "192.0.2.10", "port": "2222", "username": "probe",
              "password": "sample-password"}
    try:
        assert remote.tool("vault_save", name=name, type="ssh",
                           fields=fields).startswith("Saved credential")
        assert remote.tool("vault_get", name=name, field="host") == "192.0.2.10"
        assert remote.tool("vault_get", name=name, field="port") == "2222"
        assert remote.tool("vault_get", name=name) == "sample-password"

        described = json.loads(remote.tool("vault_describe", name=name))
        assert described["complete"] is True
        assert "value" not in described["fields"]["password"]
        assert "sample-password" not in remote.tool("vault_describe", name=name)
    finally:
        remote.tool("vault_delete", name=name)

    assert "ERROR" in remote.tool("vault_get", name=name)
