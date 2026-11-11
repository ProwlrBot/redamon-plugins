# bounty-ops

Surfaces hunt journal data, active targets, and security findings from the ProwlrBot bug bounty workspace (`/data/hunt-memory`). Requires the host's `hunt-memory` directory to be mounted into the plugin-runner container.

## Actions

| Action | Description |
|---|---|
| `sync_journal` | Parse `journal.jsonl` and cache active targets in `sdk.data` |
| `list_targets` | Return active targets (auto-syncs if cache is empty) |
| `list_findings` | Return all logged findings |
| `log_finding` | Extract a security finding from the current chat session using the LLM |

## Setup

Add `docker-compose.override.yml` to the redamon stack root:

```yaml
services:
  plugin-runner:
    volumes:
      - /root/claude-bug-bounty/hunt-memory:/data/hunt-memory:ro
```

Then restart the plugin-runner:

```bash
docker compose restart plugin-runner
```

## Permissions

- `session:read` — read the current chat session transcript for finding extraction
- `llm:invoke` — call the platform LLM to extract findings from session text

## Data

All data is stored project-scoped in `sdk.data`:

| Key | TTL | Content |
|---|---|---|
| `journal_entries` | 1h | Last 100 journal entries |
| `active_targets` | 1h | Deduplicated target list |
| `findings` | persistent | All logged findings (max 500) |
