# recon-sync

Tracks recon output freshness across all active bug bounty targets. Reads subdirectory structure from `/data/hunt-memory/<target>/recon/` and reports per-target host/URL counts and staleness.

## Actions

| Action | Description |
|---|---|
| `sync_recon` | Scan all target recon dirs and cache stats in `sdk.data` |
| `list_targets` | Return all targets with recon stats (auto-syncs if cache is empty) |
| `get_stale` | Return only targets whose recon is older than 24h or missing |

## Setup

Same volume mount as `bounty-ops` — add `docker-compose.override.yml`:

```yaml
services:
  plugin-runner:
    volumes:
      - /root/claude-bug-bounty/hunt-memory:/data/hunt-memory:ro
```

## Recon file detection

The scanner looks for files matching these patterns inside `<target>/recon/`:

- `subfinder*`, `dnsx*`, `httpx*`, `hosts*`, `subdomains*` → counted as host lines
- `katana*`, `gau*`, `wayback*`, `urls*` → counted as URL lines

## Staleness threshold

A target is marked stale when its newest recon file is older than 24h, or when no recon directory exists.

## Data

| Key | TTL | Content |
|---|---|---|
| `recon_targets` | 1h | Per-target stats array |
| `recon_sync_ts` | persistent | Unix timestamp of last sync |
