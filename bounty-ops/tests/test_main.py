import json
import pathlib
import tempfile
import pytest

from redamon_plugin_sdk.testing import FakeSdk, ScriptedLlm, make_context
from engine.main import sync_journal, list_targets, list_findings, log_finding, JOURNAL, HUNT_MEMORY


SAMPLE_ENTRIES = [
    {"ts": "2026-11-01T10:00:00Z", "target": "example-com", "platform": "h1", "event": "recon_started"},
    {"ts": "2026-11-02T12:00:00Z", "target": "another-target", "platform": "bugcrowd", "event": "finding_logged"},
    {"ts": "2026-11-03T08:00:00Z", "target": "example-com", "platform": "h1", "event": "finding_logged"},
]


@pytest.fixture()
def journal_file(tmp_path, monkeypatch):
    jf = tmp_path / "journal.jsonl"
    jf.write_text("\n".join(json.dumps(e) for e in SAMPLE_ENTRIES) + "\n")
    monkeypatch.setattr("engine.main.JOURNAL", jf)
    monkeypatch.setattr("engine.main.HUNT_MEMORY", tmp_path)
    return jf


@pytest.fixture()
def ctx():
    return make_context(plugin_id="bounty-ops", project_id="proj-1", session_id="s1", job_id="j1")


@pytest.mark.asyncio
async def test_sync_journal_returns_counts(ctx, journal_file):
    result = await sync_journal(ctx, {})
    assert result["synced"] == 3
    assert result["targets"] == 2


@pytest.mark.asyncio
async def test_sync_journal_missing_file(ctx, monkeypatch, tmp_path):
    monkeypatch.setattr("engine.main.JOURNAL", tmp_path / "nonexistent.jsonl")
    result = await sync_journal(ctx, {})
    assert result["synced"] == 0


@pytest.mark.asyncio
async def test_list_targets_after_sync(ctx, journal_file):
    await sync_journal(ctx, {})
    result = await list_targets(ctx, {})
    names = [t["target"] for t in result["targets"]]
    assert "example-com" in names
    assert "another-target" in names


@pytest.mark.asyncio
async def test_list_targets_triggers_sync_when_empty(ctx, journal_file):
    result = await list_targets(ctx, {})
    assert len(result["targets"]) == 2


@pytest.mark.asyncio
async def test_list_findings_empty_on_fresh_start(ctx):
    result = await list_findings(ctx, {})
    assert result["findings"] == []
    assert result["count"] == 0


@pytest.mark.asyncio
async def test_log_finding_extracts_from_session():
    finding_json = json.dumps({
        "has_finding": True,
        "title": "IDOR on /api/orders",
        "target": "example-com",
        "vuln_class": "idor",
        "severity": "high",
        "url": "https://example.com/api/orders/123",
        "summary": "Attacker can read any order by changing the ID.",
        "evidence": "GET /api/orders/999 returned another user's data.",
    })
    llm = ScriptedLlm([finding_json])
    transcript = {
        "id": "s1",
        "messages": [
            {"role": "user", "content": "I found an IDOR on /api/orders"},
            {"role": "assistant", "content": "Let me verify that..."},
        ],
    }
    ctx = make_context(plugin_id="bounty-ops", project_id="proj-1", session_id="s1", job_id="j1",
                       llm=llm, transcript=transcript)
    result = await log_finding(ctx, {})
    assert result["logged"] is True
    assert result["finding"]["vuln_class"] == "idor"
    assert result["finding"]["severity"] == "high"


@pytest.mark.asyncio
async def test_log_finding_no_finding_in_session():
    llm = ScriptedLlm(['{"has_finding": false}'])
    transcript = {
        "id": "s2",
        "messages": [{"role": "user", "content": "Just asking about DNS records"}],
    }
    ctx = make_context(plugin_id="bounty-ops", project_id="proj-1", session_id="s2", job_id="j2",
                       llm=llm, transcript=transcript)
    result = await log_finding(ctx, {})
    assert result["logged"] is False
    assert "reason" in result


@pytest.mark.asyncio
async def test_log_finding_persists_to_data(journal_file):
    finding_json = json.dumps({
        "has_finding": True,
        "title": "SQLi in search",
        "target": "example-com",
        "vuln_class": "sqli",
        "severity": "critical",
        "url": "https://example.com/search",
        "summary": "SQL injection in search param.",
        "evidence": "' OR 1=1-- returned all rows",
    })
    llm = ScriptedLlm([finding_json])
    transcript = {"id": "s3", "messages": [{"role": "user", "content": "SQLi found"}]}
    ctx = make_context(plugin_id="bounty-ops", project_id="proj-1", session_id="s3", job_id="j3",
                       llm=llm, transcript=transcript)
    await log_finding(ctx, {})
    result = await list_findings(ctx, {})
    assert result["count"] == 1
    assert result["findings"][0]["vuln_class"] == "sqli"
