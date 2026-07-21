# Module 8 — Complex Analysis

Repeatable workflows for multi-step analysis that go beyond a single scan or
lookup. Two workflows:

1. **Threat intel processing** (`/ingest-ti`) — ingest a threat-intel report URL,
   extract ATT&CK-mapped TTPs + IOCs, and produce a simulation plan. See
   `.claude/commands/ingest-ti.md`; output lands in `analysis/`.
2. **Multi-source investigation** (`/investigate-multi`) — correlate endpoint and
   cloud logs against each other into one attack narrative, map it to ATT&CK, and
   write an investigation note. This is the cross-source counterpart to Module 6's
   single-EVTX `/investigate`.

This README covers the multi-source investigation workflow.

## Multi-source investigation

### Log sources & layout

Point the workflow at a `logs/` directory holding four sources:

```
logs/
  endpoint/          # Windows Event XML (as emitted by wevtutil / Get-WinEvent)
    security-*.xml   #   Windows Security events (4624 logon, 4662 DCSync, ...)
    sysmon-*.xml     #   Sysmon events (EventID 1 process, 3 network, 10 process access)
  cloud/             # JSON (Graph / Log Analytics export shape)
    aad-signin-*.json
    aad-audit-*.json
```

The bundled `logs/` is a **synthetic seeded scenario** (a cloud-to-endpoint
account compromise of `j.rivera`) used to build and test the workflow — not real
data. Endpoint logs are Windows Event **XML** rather than binary EVTX so the
samples are human-readable and parseable by extending the ElementTree approach in
`../../sysmon-parser/parser.py`.

### `correlate.py` — the correlation engine

Normalizes every record to a common schema
(`ts, source, event_type, actor, host, src_ip, dest_ip, summary`), unifying
`DOMAIN\user` and `user@domain` to one actor key, then finds **cross-source
links** — the same actor or IP appearing in ≥2 sources within a sliding time
window.

```bash
# Windows: use `py`; elsewhere `python3`
py correlate.py --logs-dir logs/ --format timeline    # human-readable
py correlate.py --logs-dir logs/ --format json        # events + correlations + stats
py correlate.py --logs-dir logs/ --format md          # timeline table + correlations (for the note)
py correlate.py --logs-dir logs/ --format stats       # counts by source, distinct actors/IPs

# Focus / tune
py correlate.py --logs-dir logs/ --user 'INSECUREBANK\j.rivera'   # any user form works
py correlate.py --logs-dir logs/ --ip 45.155.205.233
py correlate.py --logs-dir logs/ --window 2h                      # default 30m; e.g. 90s, 2h
```

Stdlib only — no dependencies.

### `/investigate-multi` — the orchestrated workflow

`.claude/commands/investigate-multi.md` drives the full analysis: validate input,
run `correlate.py`, reconstruct the narrative, map behaviors to ATT&CK via
`../../Module-5/mcp-detection-kb/mappings/attack_techniques.json`, and write a note
from `templates/correlation-investigation-template.md` into `investigations/`.

```
/investigate-multi [logs_dir] [user] [window] [output_dir]
/investigate-multi logs/
```

**ATT&CK coverage honesty:** that mapping file is credential-access-focused, so
endpoint credential-theft techniques (`T1003.001` LSASS, `T1003.006` DCSync) map
as *covered*, while the cloud + lateral-movement techniques (`T1078.004`,
`T1098.003`, `T1556.006`, `T1528`, `T1021.001`, `T1071`) are reported as **gaps**
rather than guessed — the same rule as Module 6's `/investigate`. Extending the
mapping with cloud techniques is a documented follow-up.

See `investigations/2026-07-19_multi-source-jrivera.md` for a completed example.
It is fed by two per-source working notes —
`investigations/2026-07-19_endpoint-jrivera.md` (Windows Security + Sysmon) and
`investigations/2026-07-19_cloud-jrivera.md` (Azure AD sign-in + audit) — that
each analyze one side in isolation before the correlated note stitches them
together. All three cross-reference each other.

## Directory structure

```
correlate.py                          # normalization + correlation engine
logs/                                 # synthetic seeded sample logs (4 sources)
templates/
  correlation-investigation-template.md
investigations/
  2026-07-19_multi-source-jrivera.md  # example output (correlated note)
  2026-07-19_endpoint-jrivera.md      #   per-source note: Windows Security + Sysmon
  2026-07-19_cloud-jrivera.md         #   per-source note: Azure AD sign-in + audit
analysis/                             # /ingest-ti output (threat-intel workflow)
.claude/commands/
  investigate-multi.md                # multi-source investigation command
  ingest-ti.md                        # threat-intel ingestion command
```

## Verification

From this directory:

```bash
py correlate.py --logs-dir logs/ --format timeline   # cloud events precede endpoint; one ordered timeline
py correlate.py --logs-dir logs/ --format json       # j.rivera AND 45.155.205.233 each link all 4 sources
py correlate.py --logs-dir logs/ --user j.rivera@insecurebank.local --format stats  # UPN and DOMAIN\user collapse to one actor
```

Expected: `j.rivera` and `45.155.205.233` each correlate across all four sources;
the 13:24 baseline sign-in is excluded from the link by the window gap; and the
single-source `a.chen` event produces no cross-source link (negative case).
