"""End-to-end test of the real stdio transport (subprocess + JSON-RPC).

Talks to ``python -m vault_mcp.stdio`` exactly like an agent client would, so it
covers the wiring the in-process tests cannot: argument schemas, the JSON-RPC
envelope and the process lifecycle.
"""

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.integration


class StdioClient:
    def __init__(self, vault_dir: Path, user: str = "tester"):
        env = dict(os.environ)
        env.update({
            "VAULT_DIR": str(vault_dir),
            "VAULT_FORCE_PBKDF2": "1",
            "VAULT_MASTER_PASSWORD": "test-master-key-not-a-secret",
            "VAULT_USER": user,
        })
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "vault_mcp.stdio"],
            cwd=str(REPO_ROOT), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        self._id = 0

    def _read(self, timeout=20):
        # A JSON-RPC client must never hang the test run: if the server stops
        # answering, kill it and fail with a readable message instead of
        # blocking until the outer runner gives up.
        box = {}

        def _pull():
            box["line"] = self.proc.stdout.readline()

        t = threading.Thread(target=_pull, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            self.proc.kill()
            raise TimeoutError(
                "stdio server produced no response within %ss; stderr=%r"
                % (timeout, self.proc.stderr.read()[:400]))
        line = (box.get("line") or "").strip()
        if not line:
            raise RuntimeError("stdio closed: " + self.proc.stderr.read()[:800])
        return json.loads(line)

    def rpc(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            # A notification must NOT carry an id — sending one makes the SDK
            # treat it as an unexpected request and the session stalls.
            self._id += 1
            msg["id"] = self._id
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if notify:
            return None
        res = self._read()
        assert "error" not in res, res["error"]
        return res["result"]

    def tool(self, _tool_name, **args):
        res = self.rpc("tools/call", {"name": _tool_name, "arguments": args})
        return res["content"][0]["text"]

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture()
def client(tmp_path):
    c = StdioClient(tmp_path / "vault")
    c.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "pytest", "version": "1.0"}})
    c.rpc("notifications/initialized", notify=True)
    yield c
    c.close()


def test_tools_are_advertised_with_the_expected_schema(client):
    tools = {t["name"]: t for t in client.rpc("tools/list")["tools"]}
    assert set(tools) == {"vault_save", "vault_get", "vault_describe",
                          "vault_list", "vault_delete"}
    get_props = tools["vault_get"]["inputSchema"]["properties"]
    assert "field" in get_props
    assert "field" not in tools["vault_get"]["inputSchema"].get("required", [])
    assert "value" not in tools["vault_save"]["inputSchema"].get("required", [])


def test_save_read_describe_delete_over_the_wire(client):
    fields = {"host": "192.0.2.10", "port": "2222", "username": "demo",
              "password": "sample-password"}
    assert client.tool("vault_save", name="wire", type="ssh",
                       fields=fields).startswith("Saved credential")

    assert client.tool("vault_get", name="wire") == "sample-password"
    assert client.tool("vault_get", name="wire", field="host") == "192.0.2.10"
    assert client.tool("vault_get", name="wire", field="port") == "2222"

    described = json.loads(client.tool("vault_describe", name="wire"))
    assert described["complete"] is True
    assert "value" not in described["fields"]["password"]
    assert "sample-password" not in client.tool("vault_describe", name="wire")

    assert json.loads(client.tool("vault_list"))[0]["complete"] is True
    assert client.tool("vault_delete", name="wire").startswith("Deleted")
    assert json.loads(client.tool("vault_list")) == []


def test_bad_shapes_are_rejected_over_the_wire(client):
    assert "unknown credential type" in client.tool(
        "vault_save", name="x", type="bogus", fields={})
    assert "unknown field" in client.tool(
        "vault_save", name="x", type="ssh", fields={"ip": "192.0.2.10"})
    assert json.loads(client.tool("vault_list")) == []


def test_process_exits_cleanly(client):
    client.close()
    assert client.proc.returncode == 0
    assert "Traceback" not in client.proc.stderr.read()
