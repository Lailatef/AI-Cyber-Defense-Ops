# complex-analysis (Module 8)

Two **repeatable multi-step analysis workflows** — the kind that go beyond a single scan or lookup and are structured so they produce consistent output regardless of who runs them or when. Both are Claude Code slash commands with supporting code and content:

1. **Threat-intel processing** — `/ingest-ti <url>` (`.claude/commands/ingest-ti.md`): pull a threat-intel report, extract ATT&CK-mapped TTPs + IOCs, and produce an Atomic-Red-Team simulation plan. Output lands in `analysis/`.
2. **Multi-source investigation** — `/investigate-multi [logs_dir] [user] [window] [output_dir]` (`.claude/commands/investigate-multi.md`), backed by `correlate.py`: correlate endpoint **and** cloud logs against each other into one attack narrative, map it to ATT&CK, and write an Obsidian-compatible investigation note.

Beyond the two workflows, this module also builds and honestly assesses a **local-model verification stack** (Ollama + LiteLLM) as a "cheap second opinion" on analysis output — including a documented structural limitation of Claude Code that makes the obvious version of that workflow not work.

## What's new vs. Modules 3–7

Modules 3–5 are MCP servers; Module 6 is a single-source `/investigate` slash command over EVTX; Module 7 is event-driven hooks. Module 8 adds two things neither prior module has:

- **Cross-source correlation.** Module 6's `/investigate` is Hayabusa/EVTX-only — one log source. `/investigate-multi` is the point of departure: it unifies four sources (Windows Security + Sysmon on the endpoint side, Azure AD sign-in + audit on the cloud side) that no other module touches, on the premise that *no single source shows the whole intrusion*.
- **Multi-model analysis** — the same report analyzed independently by two different Claude models (Sonnet and Opus) to surface divergences, and a local 3B model wired in as a throwaway reviewer. This module is as much about *how much to trust an analysis* as about producing one.

---

## 1. Threat-intel processing — `/ingest-ti` (8.1–8.2)

### The command

```
/ingest-ti <report-url>
```

`.claude/commands/ingest-ti.md` runs a fixed pipeline: **extract → analyze → write**.

1. **Extract** — shells out to **`defuddle`** (`defuddle parse "$url" --markdown`) to strip a report page down to clean markdown before any analysis. Content extraction is deliberately a separate, deterministic step rather than asking the model to read raw HTML.
2. **Analyze** — map observed behaviors to MITRE ATT&CK (per-tactic), assign a confidence level per technique based on how much detail the report actually gives, and pull IOCs.
3. **Write** — emit `analysis/ti-<date>-<campaign>.md` with frontmatter (source URL, extraction date), TTP table, IOCs, and an Atomic-Red-Team simulation plan prioritized by *high confidence + an atomic actually exists*.

### Test case: CISA AA26-194A (FSB Center 16)

The workflow was exercised against a real advisory: **CISA AA26-194A**, the FSB Center 16 campaign targeting poorly configured / vulnerable networking devices (routers) — SNMP-based theft of Cisco device configs, TFTP exfil to leased VPS, harvesting weak Cisco type 0/7 password hashes. Two known-exploited CVEs (CVE-2018-0171 Smart Install RCE, CVE-2008-4128 EOL-only). Output: `analysis/ti-2026-07-20-fsb-center-16.md`.

This was a genuinely useful stress test because the campaign is **network-device-centric with no host-side malware** — which means most of Atomic Red Team (a Windows/Linux/macOS host framework) tests the *wrong context* for it. The simulation plan says so explicitly rather than padding itself with green-checkmark atomics that prove nothing about catching this actor: the top priority is a **custom** SNMP Config-Copy test (T1602.001/.002) against a lab router, since no atomic exists; the only recommended real atomic is **T1048.003** (exfil over unencrypted non-C2 protocol) for the TFTP leg.

### Sonnet vs. Opus — an independent second analysis

The same raw `defuddle` extraction was then re-analyzed **independently by Opus 4.8** (`analysis/ti-2026-07-20-fsb-center-16-opus.md`, `analyst_note` explicitly records it was reasoned from the raw extraction, *not* derived from the Sonnet pass). This is the threat-intel analogue of the multi-model idea below.

**Where they converged** (raising confidence the mapping is right): the same technique set and CVEs, the same "don't force Windows host atomics onto a network-device campaign" call, and the same prioritized simulation sequence (custom SNMP config-copy first, T1048.003 TFTP second).

**What the Opus pass added independently** — things the Sonnet pass didn't surface:
- **Mapping-fidelity critiques of CISA's *own* ATT&CK choices.** It flags several of the advisory's technique IDs as *loose*: T1569 (System Services) for an SNMP MIB write is a stretch (T1569's sub-techniques are OS service managers); T1027 (Obfuscated Files) for source-IP spoofing is closer to masquerading/indicator-removal in spirit; T1003 (OS Credential Dumping) for pulling creds out of a router config overlaps and is more precisely T1602.002 — i.e. one behavior double-mapped. It kept the advisory's IDs but tagged them low-fidelity rather than passing them through uncritically.
- **The Salt Typhoon overlap** — the advisory's explicit note that these TTPs overlap with the PRC actor Salt Typhoon and the mitigations counter both.
- **A repo coverage-gap analysis** — a concrete finding for *this* repo: the endpoint detection assets in Modules 3–6 (Hayabusa/Sigma over EVTX) and `sysmon-parser/` are Windows-host-event-log based and **will not see any part of this campaign** — there's no Security/Sysmon event for an SNMP Set-Request against a Cisco router. Detecting FSB Center 16 needs network telemetry (NetFlow/IPFIX, IDS on SNMP Set-Requests, network-device syslog) this repo doesn't ingest.

The value here isn't that one model "won" — it's that a second independent pass caught mapping nuances and a repo-specific gap a single pass missed.

---

## 2. Multi-source investigation — `/investigate-multi` (8.3–8.4)

### Scoping the scenario with Plan Mode

The synthetic scenario and correlation engine were designed under **Plan Mode** first — used to scope what the four-source scenario needed to demonstrate (a genuine cloud→endpoint hand-off, a positive correlation on two independent keys, and at least one deliberately-excluded negative case) before writing any logs or code.

### The synthetic `j.rivera` cloud-to-endpoint compromise

`logs/` is a **synthetic seeded scenario** — a single compromised identity, `j.rivera`, whose activity spans all four sources in an ~18-minute window on 2026-07-19 (not real data). The chain:

1. **Impossible-travel sign-in** — a high-risk Azure AD sign-in from `45.155.205.233` (Bucharest, RO) ~38 min after a benign US baseline; MFA "satisfied by claim in the token" (no fresh prompt).
2. **MFA persistence** — attacker registers a new Microsoft Authenticator method.
3. **Privileged role grant** — self-adds to **Privileged Role Administrator**.
4. **OAuth consent abuse** — consents an illicit mail-reading app (eM Client: Mail.Read, offline_access, IMAP).
5. **RDP hand-off** — a type-10 logon to `WKSTN-07` from the *same* IP.
6. **Mimikatz / LSASS dump** — a masqueraded `svc-host.exe` (OriginalFileName `mimikatz.exe`) runs `sekurlsa::logonpasswords`, opens `lsass.exe`.
7. **C2 beacon** — back to `45.155.205.233:443`.
8. **DCSync** — 4662 replication-rights object access on `DC1`.

The endpoint side is deliberately **Windows Event XML** (what `wevtutil` / `Get-WinEvent` emit), not binary EVTX — real EVTX can't be hand-synthesized, and the XML form is human-readable and parseable. The Sysmon field-extraction idiom reuses `../../sysmon-parser/parser.py`, generalized beyond EventID 1.

### `correlate.py` — the deterministic correlation engine

Stdlib-only. It normalizes every record from all four sources to one schema (`ts, source, event_type, actor, host, src_ip, dest_ip, summary`), **unifying `DOMAIN\user` and `user@domain` to one actor key**, then links events that share an actor or IP within a sliding time window (default 30m). DCSync 4662s are flagged via the two replication control-access GUIDs (`1131f6aa…` / `1131f6ad…`).

```bash
# use `py` on Windows; python3/python elsewhere
py correlate.py --logs-dir logs/ --format timeline   # human-readable ordered timeline
py correlate.py --logs-dir logs/ --format json       # events + correlations + stats
py correlate.py --logs-dir logs/ --format md         # timeline + correlations table for the note
py correlate.py --logs-dir logs/ --format stats      # counts by source, distinct actors/IPs
py correlate.py --logs-dir logs/ --user 'INSECUREBANK\j.rivera'  # any user form works
py correlate.py --logs-dir logs/ --ip 45.155.205.233
py correlate.py --logs-dir logs/ --window 2h         # default 30m; e.g. 90s, 2h
```

**Verification tests run** against the seeded scenario:
- **Positive correlation** — both `j.rivera` (across the UPN/`DOMAIN\user` forms) and `45.155.205.233` each link all four sources.
- **Identity normalization** — querying `--user j.rivera@insecurebank.local` returns the same actor as the `DOMAIN\user` form (UPN and down-level name collapse to one key).
- **Baseline exclusion** — the 13:24 pre-incident US sign-in is split out of the `j.rivera` link by the 30m window gap.
- **Negative case** — `a.chen`'s later single-source (Sysmon-only) Chrome event produces no cross-source link.

Because the engine is deterministic, it's the ground truth the LLM subagents are checked against — not the other way round.

### `endpoint-analyst` / `cloud-analyst` subagents

Two project subagents (`.claude/agents/endpoint-analyst.md`, `cloud-analyst.md`; both `tools: Read, Bash`) analyze one side each, in isolation, before correlation. Tested against the real seeded logs, they **independently converged with the deterministic correlator** on the same narrative — *and* found genuinely additional insight the correlator can't produce because it only keys on actor/IP:

- **`T1036.005` Masquerading** (endpoint) — reading the Sysmon fields, the endpoint analyst caught `svc-host.exe` carrying `OriginalFileName: mimikatz.exe`, a masquerading call `correlate.py` never makes.
- **AiTM cookie-theft inference** (cloud) — the cloud analyst read "MFA satisfied by claim in the token" + impossible travel as adversary-in-the-middle session-cookie theft, mapping **`T1539`** (Steal Web Session Cookie) — an inference from field semantics, not a key match.

### Bugs caught by verifying against the raw logs

The discipline this module pushes: **verify specific claims against source, don't trust the summary.** Two concrete catches:

- **A SHA256 typo** in the endpoint note (a duplicated hex chunk) was found and fixed, then the corrected hash (`A3E5D2C1B0F9A8E7D6C5B4A3928170F6E5D4C3B2A1908070605040302010FEDC`) was confirmed character-for-character against the raw `sysmon-wkstn07-20260719.xml`.
- **The SID (`…-1607`) and the Privileged-Role-Administrator role-template GUID (`e8611ab8-c189-46e8-94e1-60213ab1f814`)** were pulled straight from the raw files to confirm they were real values, not model-invented identifiers.

### Final structure: three cross-referenced notes

The workflow's output for this scenario is three notes in `investigations/`, each linking the others:

- `2026-07-19_endpoint-jrivera.md` — Windows Security + Sysmon (WKSTN-07, DC1)
- `2026-07-19_cloud-jrivera.md` — Azure AD sign-in + audit
- `2026-07-19_multi-source-jrivera.md` — the correlated note that stitches both together (the `/investigate-multi` example output)

**ATT&CK honesty rule** (same as Module 6's `/investigate`): techniques are checked against `../../Module-5/mcp-detection-kb/mappings/attack_techniques.json`, which is credential-access-focused. Endpoint credential-theft techniques (`T1003.001` LSASS, `T1003.006` DCSync) map as *covered*; the cloud + lateral-movement techniques (`T1078.004`, `T1556.006`, `T1098.003`, `T1528`, `T1021.001`, `T1071`) are reported as **gaps**, not guessed. Extending the mapping with the cloud techniques is a documented follow-up.

### Threat context (verified)

The correlated note carries a **Threat Context** section grounding the scenario in real-world reporting: its AiTM shape (successful sign-in past MFA → attacker-registered MFA method) matches the documented pattern, cited to Microsoft's Nov 2024 Entra blog / Digital Defense Report 2024 **146% YoY rise in AiTM phishing** — dated as a **2024** measurement still being cited, *not* fresh 2026 data, with an explicit note not to confuse it with a separate ~146% Q1-2026 QR-code phishing figure. It proposes `T1557` (Adversary-in-the-Middle) and `T1539` (Steal Web Session Cookie) as more-precise candidate techniques for the initial-access mechanism than the current `T1528` (which better fits the separate OAuth-consent stage), flagged as *inferred/off-host* rather than directly logged. (Honest caveat: a web fetch in-session confirmed the citation's URL and date are correct, but the full article body wasn't retrieved, so the exact 146% figure itself is verified only to the extent of its source — not re-read line-by-line.)

---

## 3. Multi-model verification — `verify-local` (8.5)

The goal: run a **local model as a cheap second opinion** on an investigation note — flag unsupported conclusions, alternative explanations, and logical gaps — without paying for a frontier model. Building this surfaced both a hard structural limitation of Claude Code and an honest read on what a 3B reviewer is actually worth.

### The local stack

- **Ollama** (v0.32.1) serving **`llama3.2`** (3B, ~2.0 GB) on `:11434`. This machine is **CPU-only** (Intel Iris Xe integrated graphics, no dedicated NVIDIA/AMD GPU), so inference runs on CPU at ~11–12 tok/s — usable for a short review, not for driving an agent loop.
- **LiteLLM proxy** (v1.91.4) on `:4000` (`litellm-config.yaml`), exposing Ollama through both an OpenAI-compatible `/v1/chat/completions` route and an Anthropic `/v1/messages` passthrough. `master_key` is read from `os.environ/LITELLM_MASTER_KEY` (env var, not plaintext in the file).

### The Windows debugging chain (all real, all fixed)

1. **Rust/wheel build failure** — `pip install 'litellm[proxy]'` tried to build a version whose sdist needs Rust/Cargo. Fixed by forcing a prebuilt wheel: `pip install --only-binary=:all: 'litellm[proxy]'` (landed 1.91.4).
2. **Windows Unicode banner crash** — the proxy's startup banner threw `UnicodeEncodeError: 'charmap' codec` on the cp1252 console. Fixed with `PYTHONUTF8=1` (+ `PYTHONIOENCODING=utf-8`).
3. **PATH issues for both `ollama` and `litellm`** — freshly installed binaries aren't on `PATH` until the shell is restarted (winget/pip update the user PATH, but already-running shells keep their snapshot — same gotcha as Module 7's `jq`).
4. **PowerShell `curl` alias trap** — in PowerShell, `curl` is an alias for `Invoke-WebRequest`, not real curl; requests must use `curl.exe` (or run from bash).

### Key finding: `ANTHROPIC_BASE_URL` is session-global

The intended workflow — a capable Claude orchestrator that **spawns a `verify-local` subagent running on the local model** — **does not work as the tutorial describes it.** Claude Code routes *all* model calls in a session through `ANTHROPIC_BASE_URL`, which is **session-global**. Point it at the LiteLLM proxy and the *whole* session (orchestrator included) is now talking to `llama3.2`; leave it at Anthropic and the subagent can't reach the local model. There is no per-subagent base-URL override, so you structurally cannot mix a Claude orchestrator with a local-model subagent in one session.

Worse, even when a session *is* pointed entirely at the local model (`claude_local.sh` bakes in `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, and `MAX_THINKING_TOKENS=0` — the last needed because `llama3.2` returns a hard error on thinking requests), the 3B model can't reliably emit Claude Code's tool-call protocol: it returns malformed tool-call JSON instead of answering. It cannot drive the agent harness.

### The working alternative: `verify-local.sh`

`verify-local.sh` **bypasses Claude Code's subagent/tool-calling machinery entirely**. It reads an investigation file and POSTs it directly to the proxy's `/v1/chat/completions` with a critical-reviewer system prompt — a plain chat request, which a 3B model handles fine even though it can't drive tool-use. (The `verify-local.md` subagent definition is kept in the repo as documentation of the approach that *doesn't* work; `verify-local.sh` is what actually runs.)

```bash
./verify-local.sh investigations/2026-07-19_multi-source-jrivera.md
```

### Honest assessment of review quality

Run against the correlated note, `verify-local.sh` produced a **real, structured critique** — organized as unsupported conclusions / alternative explanations / logical gaps — with some legitimately reasonable observations (e.g. that the "MFA change could be a benign security improvement" is worth ruling out). Two honest caveats worth stating plainly:

- It did **not** strictly follow the requested per-finding `Agrees / Questions / Disagrees` format — it returned free-form sections instead. A 3B model follows output-format instructions loosely.
- It contained a **factual error**: it claimed the analysis interpreted `sekurlsa::logonpasswords` (event 6) as C2 communication. The analysis does no such thing — event 6 is the Mimikatz process-create; C2 is a *separate* event (8). The model conflated two timeline entries.

That's the point of the exercise: a small-model "second opinion" is a cheap prompt for *human* re-examination, **not an authority**. Its output needs verification before you act on it — exactly the discipline this module applies to its own analyses.

### The curl-arg-truncation bug

First runs of `verify-local.sh` failed with `Invalid model name passed in model=None`. Root cause: passing a ~7 KB JSON body as a curl **command-line argument** (`-d "$BODY"`) gets truncated crossing the process boundary on Windows/mingw, so the proxy received a broken request. Fixed by building the body with `jq` into a **temp file** and sending it with `curl --data-binary @file`, keeping the large payload off the command line entirely.

---

## 4. Context management (8.6)

Long analysis sessions were managed with **`/context`** (to inspect token usage by category — system prompt, tools, messages, free space) and **`/compact` with explicit preservation instructions** — compacting the transcript while naming the facts that must survive (the `j.rivera` scenario specifics, the confirmed ATT&CK IDs, the key file paths, and the `ANTHROPIC_BASE_URL` finding), so the working state carries across a compaction boundary instead of being summarized away.

---

## Setup

### `defuddle` (threat-intel workflow)

```bash
npm install -g defuddle-cli   # provides the `defuddle` command used by /ingest-ti
```

### Ollama + LiteLLM stack (verification workflow, Windows)

```bash
# 1. Ollama + model
winget install Ollama.Ollama
ollama pull llama3.2                 # ~2.0 GB

# 2. LiteLLM proxy — force a prebuilt wheel (avoids a Rust/Cargo source build)
py -m pip install --only-binary=:all: 'litellm[proxy]'
```

Both installs update the user `PATH`; **open a fresh terminal** afterward so `ollama` and `litellm` resolve.

### Relaunching after a reboot (the three moving parts)

1. **Ollama** — installs as an auto-starting Windows service on `:11434`. Confirm it's up: `ollama list` (it lists `llama3.2`). Start it manually with `ollama serve` if not.
2. **LiteLLM proxy** — one terminal, with the two env vars that make it work on Windows:
   ```powershell
   $env:PYTHONUTF8='1'                       # avoid the cp1252 banner crash
   $env:LITELLM_MASTER_KEY='sk-litellm-dev-key'
   litellm --config litellm-config.yaml --port 4000
   ```
   (If `litellm` isn't on `PATH`, call it from your Python `Scripts\litellm.exe`.)
3. **Client** — another terminal: `./verify-local.sh <note>` for a review, or `./claude_local.sh -p '…'` to route a Claude Code session at the local model. Both default `LITELLM_MASTER_KEY` to `sk-litellm-dev-key`, matching the proxy.

---

## Project structure

```
complex-analysis/
├── CLAUDE.md
├── README.md
├── correlate.py                       # stdlib multi-source normalization + correlation engine
├── .claude/
│   ├── commands/
│   │   ├── ingest-ti.md               # /ingest-ti  — threat-intel processing
│   │   └── investigate-multi.md       # /investigate-multi — cross-source investigation
│   └── agents/
│       ├── endpoint-analyst.md        # Windows Security + Sysmon subagent (Read, Bash)
│       ├── cloud-analyst.md           # Azure AD sign-in + audit subagent (Read, Bash)
│       └── verify-local.md            # local-model reviewer — kept as doc of the approach that DOESN'T work
├── logs/                              # synthetic seeded j.rivera scenario (NOT real data)
│   ├── endpoint/                      #   Windows Event XML (Security 4624/4662, Sysmon 1/3/10)
│   │   ├── security-wkstn07-20260719.xml
│   │   ├── security-dc1-20260719.xml
│   │   └── sysmon-wkstn07-20260719.xml
│   └── cloud/                         #   Azure AD JSON
│       ├── aad-signin-20260719.json
│       └── aad-audit-20260719.json
├── templates/
│   └── correlation-investigation-template.md
├── investigations/                    # three cross-referenced notes for the example scenario
│   ├── 2026-07-19_multi-source-jrivera.md   # correlated (the /investigate-multi output)
│   ├── 2026-07-19_endpoint-jrivera.md       #   per-source: endpoint
│   └── 2026-07-19_cloud-jrivera.md          #   per-source: cloud
├── analysis/                          # /ingest-ti output
│   ├── ti-2026-07-20-fsb-center-16.md       # Sonnet pass (AA26-194A)
│   └── ti-2026-07-20-fsb-center-16-opus.md  # independent Opus 4.8 re-analysis
├── litellm-config.yaml                # Ollama→OpenAI/Anthropic proxy (master_key via env var)
├── claude_local.sh                    # route a Claude Code session at llama3.2 via the proxy
└── verify-local.sh                    # direct /v1/chat/completions reviewer (the working path)
```

## Lessons learned this module

- **`ANTHROPIC_BASE_URL` is session-global — you cannot mix a Claude orchestrator with a local-model subagent in one Claude Code session.** The tidy "spawn a `verify-local` subagent on the local model" workflow is structurally impossible as written; the working shape is to bypass the harness with a direct proxy call (`verify-local.sh`). Discovered by building it, not by reading docs.
- **Independent multi-model analysis catches what a single pass misses.** The Opus re-read of AA26-194A surfaced mapping-fidelity critiques of CISA's own ATT&CK choices, the Salt Typhoon overlap, and a repo-specific coverage gap that the first pass didn't — and where the two passes *converged*, that convergence is itself evidence the mapping is sound.
- **Verify specific claims against source; don't trust summaries.** A SHA256 typo, a SID, a role-template GUID, and a 146% statistic were each checked against their origin rather than passed through — and the SHA256 was genuinely wrong until fixed. The same rule caught the local reviewer's factual misread of event 6.
- **A small local model is a cheap second opinion, not an authority.** `llama3.2` produced a usable critique *and* a confident factual error in the same output, and followed the requested format only loosely. Treat its findings as prompts for human re-examination, never as verdicts.
- **Deterministic tooling is the ground truth for probabilistic analysts.** `correlate.py` (pure key-matching) is what the LLM subagents get checked against — and precisely because it *only* matches actor/IP, the subagents earn their keep by adding semantic reads (masquerading, AiTM cookie theft) the engine can't produce.
