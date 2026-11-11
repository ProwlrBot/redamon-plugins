import time
from pathlib import Path

HUNT_MEMORY = Path("/data/hunt-memory")
STALE_HOURS = 24
COLLECTION = "recon"


def _now() -> int:
    return int(time.time())


def _count_lines(path: Path) -> int:
    try:
        with open(path) as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except Exception:
        return 0.0


def _scan_target(target_dir: Path) -> dict:
    recon_dir = target_dir / "recon"
    name = target_dir.name

    if not recon_dir.is_dir():
        return {
            "target": name,
            "has_recon": False,
            "host_count": 0,
            "url_count": 0,
            "last_recon": None,
            "age_hours": None,
            "stale": True,
        }

    host_count = 0
    url_count = 0
    latest_mtime = 0.0
    seen: set[str] = set()

    for f in recon_dir.iterdir():
        mt = _mtime(f)
        if mt > latest_mtime:
            latest_mtime = mt
        fname = f.name.lower()
        if any(tag in fname for tag in ("subfinder", "dnsx", "httpx", "hosts", "subdomains")):
            if f.name not in seen:
                seen.add(f.name)
                host_count += _count_lines(f)
        elif any(tag in fname for tag in ("katana", "gau", "wayback", "urls")):
            url_count += _count_lines(f)

    age_hours = round((_now() - latest_mtime) / 3600, 1) if latest_mtime > 0 else None

    return {
        "target": name,
        "has_recon": True,
        "host_count": host_count,
        "url_count": url_count,
        "last_recon": int(latest_mtime) if latest_mtime > 0 else None,
        "age_hours": age_hours,
        "stale": age_hours is None or age_hours > STALE_HOURS,
    }


async def sync_recon(ctx, params: dict) -> dict:
    sdk = ctx.sdk
    await sdk.jobs.progress("Scanning hunt-memory…")

    if not HUNT_MEMORY.is_dir():
        return {"error": "/data/hunt-memory not mounted", "targets": []}

    results = []
    dirs = [d for d in HUNT_MEMORY.iterdir() if d.is_dir()]
    total = len(dirs)

    for i, d in enumerate(dirs):
        if i % 5 == 0 and total > 0:
            await sdk.jobs.progress(f"Scanning {d.name}…")
        results.append(_scan_target(d))

    results.sort(key=lambda x: (x["stale"], x["target"]))

    await sdk.data.put(COLLECTION, "targets", results, owner="project", ttl_seconds=3600)
    await sdk.data.put(COLLECTION, "sync_ts", _now(), owner="project")
    await sdk.jobs.progress("Done")

    stale_count = sum(1 for r in results if r["stale"])
    return {"targets": len(results), "stale": stale_count}


async def list_targets(ctx, params: dict) -> dict:
    sdk = ctx.sdk
    targets = await sdk.data.get(COLLECTION, "targets", owner="project")
    if targets is None:
        await sync_recon(ctx, params)
        targets = await sdk.data.get(COLLECTION, "targets", owner="project")
    return {"targets": targets or []}


async def get_stale(ctx, params: dict) -> dict:
    sdk = ctx.sdk
    targets = await sdk.data.get(COLLECTION, "targets", owner="project")
    if targets is None:
        await sync_recon(ctx, params)
        targets = await sdk.data.get(COLLECTION, "targets", owner="project")
    stale = [t for t in (targets or []) if t.get("stale")]
    return {"stale": stale, "count": len(stale)}
