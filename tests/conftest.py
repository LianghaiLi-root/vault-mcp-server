"""Shared test setup.

Two rules this file exists to enforce:

1. **Never touch a real vault.** The environment below is written before any
   vault module is imported, so ``vault_core`` resolves its storage to a
   throwaway directory under the OS temp dir. Tests additionally re-point
   ``vault_core.VAULT_DIR`` per test case, so one test can never see another's
   records.
2. **No real endpoints in the suite.** ``tests/test_remote_mcp.py`` only runs
   when ``MCP_URL`` and ``MCP_TOKEN`` are supplied by the caller; nothing about
   a live deployment is baked into this repository.
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Must run at import time — before any `vault_mcp.*` import happens in a test
# module during collection.
# ---------------------------------------------------------------------------
_ROOT = Path(tempfile.mkdtemp(prefix="vault-mcp-tests-"))
_CONFIG = _ROOT / "config.yaml"
_CONFIG.write_text(
    "vault:\n"
    f"  dir: {(_ROOT / 'vault').as_posix()}\n"
    "  force_pbkdf2: true\n"
    "server:\n"
    "  host: 127.0.0.1\n"
    "  port: 8080\n"
    "users: []\n",
    encoding="utf-8",
)

os.environ["VAULT_DIR"] = str(_ROOT / "vault")
os.environ["VAULT_CONFIG"] = str(_CONFIG)
os.environ["VAULT_FORCE_PBKDF2"] = "1"
os.environ["VAULT_MASTER_PASSWORD"] = "test-master-key-not-a-secret"
# Keep every case independent of whatever namespace the host machine may have.
os.environ.pop("VAULT_USER", None)


@pytest.fixture(scope="session", autouse=True)
def _cleanup_tmp_root():
    yield
    shutil.rmtree(_ROOT, ignore_errors=True)


@pytest.fixture()
def vault(tmp_path, monkeypatch):
    """A private, empty vault for a single test."""
    import vault_mcp.vault_core as vc
    monkeypatch.setattr(vc, "VAULT_DIR", tmp_path / "vault")
    vc._VAULTS.clear()
    yield vc
    vc._VAULTS.clear()


@pytest.fixture()
def server(vault):
    """The remote server's tool layer, bound to the private vault.

    The tools resolve their namespace from a ContextVar that the HTTP auth
    middleware normally sets; here it is set directly.
    """
    from vault_mcp import server as srv
    token = srv.auth_user_ctx.set("tester")
    yield srv
    srv.auth_user_ctx.reset(token)


@pytest.fixture()
def stdio(vault, monkeypatch):
    """The stdio server's tool layer, bound to the private vault."""
    from vault_mcp import stdio as std
    monkeypatch.setenv("VAULT_USER", "tester")
    return std
