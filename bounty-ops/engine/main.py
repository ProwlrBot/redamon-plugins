import json
import time
from pathlib import Path

HUNT_MEMORY = Path("/data/hunt-memory")
JOURNAL = HUNT_MEMORY / "journal.jsonl"
COLLECTION = "hunt"


def _now() -> int:
    return int(time.time())


def _load_journal() -> list[dict]:
    if not JOURNAL.exists():
        return []
    entries = []
    with open(JOURNAL) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def _extract_targets(entries: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for e in entries:
        t = e.get("target") or e.get("program") or ""
        if not t:
            continue
        ts = e.get("ts") or e.get("timestamp") or ""
        if t not in seen or ts > seen[t]["last_entry"]:
            seen[t] = {
                "target": t,
                "platform": e.get("platform", "unknown"),
                "last_entry": ts,
                "status": "active",
            }
    return list(seen.values())


async def sync_journal(ctx, params: dict) -> dict:
    sdk = ctx.sdk
    try:
        entries = _load_journal()
    except Exception as exc:
        return {"synced": 0, "error": str(exc)}

    recent = entries[-100:]
    targets = _extract_targets(entries)

    await sdk.data.put(COLLECTION, "journal_entries", recent, owner="project", ttl_seconds=3600)
    await sdk.data.put(COLLECTION, "active_targets", targets, owner="project", ttl_seconds=3600)
    await sdk.data.put(COLLECTION, "journal_sync_ts", _now(), owner="project")

    return {"synced": len(entries), "targets": len(targets)}


async def list_targets(ctx, params: dict) -> dict:
    sdk = ctx.sdk
    targets = await sdk.data.get(COLLECTION, "active_targets", owner="project")
    if targets is None:
        await sync_journal(ctx, params)
        targets = await sdk.data.get(COLLECTION, "active_targets", owner="project")
    return {"targets": targets or []}


async def list_findings(ctx, params: dict) -> dict:
    sdk = ctx.sdk
    findings = await sdk.data.get(COLLECTION, "findings", owner="project") or []
    return {"findings": findings, "count": len(findings)}


async def log_finding(ctx, params: dict) -> dict:
    sdk = ctx.sdk
    await sdk.jobs.progress("Reading session…")

    session = await sdk.session.read()
    if not session:
        return {"logged": False, "error": "No active session"}

    messages = session.get("messages", [])
    if not messages:
        return {"logged": False, "error": "Session has no messages"}

    transcript = "\n\n".join(
        f"[{m.get('role', 'unknown').upper()}]\n{str(m.get('content', ''))[:2000]}"
        for m in messages[-20:]
    )

    await sdk.jobs.progress("Extracting finding with LLM…")

    prompt = (
        "You are a bug bounty triage assistant. Extract the most significant security "
        "finding from this chat session transcript, if one is present.\n\n"
        "Return ONLY a JSON object with these exact fields:\n"
        '{"title":"","target":"","vuln_class":"","severity":"critical|high|medium|low|info",'
        '"url":"","summary":"","evidence":"","has_finding":true}\n\n'
        "If no security finding is present, return only: {\"has_finding\":false}\n\n"
        f"TRANSCRIPT:\n{transcript}"
    )

    result = await sdk.llm.invoke(
        [{"role": "user", "content": prompt}],
        max_tokens=512,
        temperature=0.1,
    )

    text = (result.get("content") or "").strip()
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == 0:
        return {"logged": False, "error": "LLM returned no JSON", "raw": text[:200]}

    try:
        finding = json.loads(text[start:end])
    except json.JSONDecodeError as exc:
        return {"logged": False, "error": f"JSON parse failed: {exc}", "raw": text[start:end][:200]}

    if not finding.get("has_finding"):
        return {"logged": False, "reason": "No security finding detected in session"}

    finding.pop("has_finding", None)
    finding["logged_at"] = _now()
    finding["session_id"] = session.get("id", "")

    await sdk.jobs.progress("Saving finding…")

    findings = await sdk.data.get(COLLECTION, "findings", owner="project") or []
    findings.append(finding)
    await sdk.data.put(COLLECTION, "findings", findings[-500:], owner="project")

    return {"logged": True, "finding": finding}
