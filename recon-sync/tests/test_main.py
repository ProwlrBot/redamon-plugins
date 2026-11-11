import json
import time
import pytest

from redamon_plugin_sdk.testing import make_context
from engine.main import sync_recon, list_targets, get_stale


@pytest.fixture()
def hunt_memory(tmp_path, monkeypatch):
    # Build a fake hunt-memory tree
    for name, hosts, urls in [
        ("example-com", 15, 200),
        ("another-target", 0, 0),  # has recon dir but empty
        ("no-recon-target", None, None),  # no recon dir at all
    ]:
        d = tmp_path / name
        d.mkdir()
        if hosts is not None:
            recon = d / "recon"
            recon.mkdir()
            # subfinder output
            sf = recon / "subfinder-example-com.txt"
            sf.write_text("\n".join(f"sub{i}.example.com" for i in range(hosts)))
            # katana output
            kt = recon / "katana-example-com.txt"
            kt.write_text("\n".join(f"https://example.com/page{i}" for i in range(urls)))

    monkeypatch.setattr("engine.main.HUNT_MEMORY", tmp_path)
    return tmp_path


@pytest.fixture()
def ctx():
    return make_context(plugin_id="recon-sync", project_id="proj-1", session_id="s1", job_id="j1")


@pytest.mark.asyncio
async def test_sync_recon_counts_targets(ctx, hunt_memory):
    result = await sync_recon(ctx, {})
    assert result["targets"] == 3


@pytest.mark.asyncio
async def test_sync_recon_counts_stale(ctx, hunt_memory):
    result = await sync_recon(ctx, {})
    # all files are brand new so age_hours ≈ 0 — not stale for example-com and another-target
    # no-recon-target has no recon dir so it's stale
    assert result["stale"] >= 1


@pytest.mark.asyncio
async def test_list_targets_returns_data(ctx, hunt_memory):
    await sync_recon(ctx, {})
    result = await list_targets(ctx, {})
    names = [t["target"] for t in result["targets"]]
    assert "example-com" in names
    assert len(result["targets"]) == 3


@pytest.mark.asyncio
async def test_list_targets_triggers_sync_when_empty(ctx, hunt_memory):
    result = await list_targets(ctx, {})
    assert len(result["targets"]) == 3


@pytest.mark.asyncio
async def test_get_stale_filters_correctly(ctx, hunt_memory):
    await sync_recon(ctx, {})
    result = await get_stale(ctx, {})
    stale_names = [t["target"] for t in result["stale"]]
    assert "no-recon-target" in stale_names


@pytest.mark.asyncio
async def test_no_hunt_memory_mount(ctx, monkeypatch, tmp_path):
    monkeypatch.setattr("engine.main.HUNT_MEMORY", tmp_path / "nonexistent")
    result = await sync_recon(ctx, {})
    assert "error" in result
    assert result["targets"] == []


@pytest.mark.asyncio
async def test_host_count_reads_subfinder(ctx, hunt_memory):
    await sync_recon(ctx, {})
    result = await list_targets(ctx, {})
    ec = next(t for t in result["targets"] if t["target"] == "example-com")
    assert ec["host_count"] == 15
    assert ec["url_count"] == 200
