# Module 9 — Executive Reporting & Interactive Artifacts (Claude Desktop)

Everything in Modules 3–8 runs through **Claude Code** — MCP servers, slash commands, hooks, subagents. Module 9 is the first module built in **Claude Desktop** instead, and it uses the features Desktop has that the CLI doesn't: **document generation** (Office files as real `.docx`/`.pptx`), **interactive artifacts** (live React components), **Cowork** (a cross-file working session over a folder of notes), and **Connectors** (Google Drive, GitHub). The point of departure is deliverable *format*: Module 8 produced Markdown investigation notes for an analyst audience; Module 9 turns those same findings into the things an IR engagement actually hands over — a formal incident report, an executive slide deck, and two interactive dashboards.

Crucially, this is **not** a from-scratch scenario. Every fact in these deliverables traces back to Module 8's `j.rivera` cloud-to-endpoint compromise (`../Module-8/complex-analysis/investigations/`) — the same 18-minute chain, the same ATT&CK IDs, the same IOCs, the same detection-coverage gaps from Module 5's mapping. Module 9's job is *presentation and consistency*, and the interesting failures here are all about that: an overconfident claim that slipped from a source note into a summary, and a connector upload that "succeeded" while sending the wrong bytes.

## What's new vs. Modules 3–8

- **A different harness.** Claude Desktop, not Claude Code. No `.claude/` project config, no slash commands — the module is a set of produced artifacts plus a written account of the Desktop-only features used to make them.
- **Binary deliverables, not Markdown.** Real Office documents (`.docx`, `.pptx`) generated in-session, and React artifacts meant to be *run*, not read.
- **Cowork as a consistency checker.** Module 8's discipline was "verify claims against source." Module 9 applies the same discipline at the *cross-file* level — running a consistency pass over all four Module 8 notes at once, which caught a real accuracy defect (below).
- **Connectors, and their uneven reality.** Google Drive and GitHub both show "Connected," but only one of them actually exposes a usable API tool in this chat. That asymmetry is a finding, not a footnote.

---

## The four deliverables

All four were generated from the Module 8 `j.rivera` findings. File sizes are the actual on-disk artifacts in this directory.

### 1. `Incident_Response_Report_IR-2026-0719-001.docx` — formal incident report (~30 KB)

A complete Word incident report, structured the way a real IR deliverable is:

- **Cover page** and an auto-generated **Table of Contents**.
- **1. Executive Summary** (with Key Recommendations) — written for a reader who won't get past page one.
- **2. Incident Details** — Detection, Timeline, Scope, Attack Chain.
- **3. Technical Analysis** — **ATT&CK mapping split into *Confirmed* (directly observed in evidence) vs. *Candidate* (inferred, not directly logged)**, a **Detection Coverage** table, an **Indicators of Compromise** section, and Evidence Collected.
- **4. Impact Assessment** — Data at Risk, Systems Affected, Business Operations Impact.
- **5. Containment & Remediation** — Immediate Actions, Short-Term steps, Long-Term Improvements.
- **6. Recommendations** — prioritized improvements + detection gaps to address.
- **7. Appendices** — full IOC list, raw timeline reference, references.

The confirmed/candidate split is inherited straight from Module 8's ATT&CK-honesty rule: techniques directly seen in logs are separated from the ones inferred off-host (AiTM / session-cookie theft), so the report never presents an inference as a logged fact.

### 2. `Security_Incident_Briefing.pptx` — executive presentation (~223 KB, 8 slides)

An 8-slide deck aimed at a **non-technical executive** audience — deliberately plain language, no raw log fields:

1. **Title** — j.rivera Cloud-to-Endpoint Account Compromise
2. **What Happened** — the incident in business terms
3. **Timeline** — the 14:02–14:20 attack flow
4. **Business Impact** — what's at risk
5. **Our Response** — detection & investigation
6. **Recommendations** — quick wins first
7. **Next Steps** — concrete action items
8. **Questions / Contact** — SOC contact

The deck carries an attack-flow narrative and the same timeline as the report, but recast so a reader who doesn't know what "DCSync" or "type-10 logon" means still understands the severity and the ask.

### 3. `detection-coverage-dashboard.jsx` — interactive coverage dashboard (~11 KB)

A live React artifact showing **real** ATT&CK coverage for this incident, checked against **Module 5's curated detection-rule mapping** (credential-access focused). Eight techniques were observed; only two are covered:

- **Covered (2):** `T1003.001` LSASS Memory, `T1003.006` DCSync — both endpoint credential-dumping, both in Module 5's mapping.
- **Gaps (6):** `T1078.004`, `T1556.006`, `T1098.003`, `T1528`, `T1021.001`, `T1071` — the cloud and lateral-movement techniques, which Module 5's mapping doesn't yet track.

That's **2 of 8 covered → a 75% gap**, and the dashboard says so honestly rather than guessing coverage: it renders a coverage meter, a per-technique bar chart (sorted worst-first), and a filterable technique list with a "show gaps only" toggle, each row tied to the specific incident event that evidenced the technique. The "not yet tracked = reported as a gap, not guessed" rule is stated in the footer — the same posture as Module 8's investigation notes.

### 4. `attack-timeline.jsx` — interactive attack timeline (~11 KB)

A live React timeline of the eight incident events. What makes it more than a static list:

- **Elapsed-time-accurate node positions** — each node is placed by its real `minutesFromStart`, so the horizontal spacing *is* the pacing of the attack. The dense 14:18–14:20 cluster (Mimikatz → C2 → DCSync) visibly contrasts with the wider gaps earlier.
- **Zoom** (three levels) to spread that dense tail out.
- **Click-for-detail** — selecting any node opens a panel with the cloud/endpoint source, timestamp, ATT&CK technique, and the full evidence detail for that event.
- **Honest exclusions** — a caption notes that the pre-incident baseline sign-in (13:24) and an unrelated single-source event (14:30) were evaluated and *correctly excluded* on correlation grounds — carrying Module 8's negative-case discipline into the visualization.

---

## Cowork — the cross-file completeness check (and the bug it caught)

The most valuable thing Module 9 did wasn't generating a document — it was **running a Cowork consistency pass across all four Module 8 investigation notes at once** before trusting any of them as source material.

That pass caught a **real accuracy defect**: the **Privileged Role Administrator grant** was stated as **confirmed fact** in one summary, when the underlying source note actually flagged it as **unconfirmed** — the evidence was ambiguous between a genuine self-escalation and possible **log denormalization** (the same grant showing up twice through how the logs were flattened). The summary had quietly promoted a hedged, uncertain finding into a hard claim.

Because this was caught *before* the formal deliverables were finalized, **both the DOCX and the PPTX were corrected** to reflect the finding's real (candidate/unconfirmed) status rather than overstating it. This is exactly why the report's ATT&CK section keeps a Confirmed-vs-Candidate split.

Full findings: [`../Module-8/complex-analysis/investigations/completeness-check.md`](../Module-8/complex-analysis/investigations/completeness-check.md).

---

## Connectors — Google Drive vs. GitHub

Two connectors were exercised, with very different results.

### Google Drive (native API — worked, after a caught mistake)

Google Drive was connected and used to save the **corrected** DOCX report. It exposes a direct API tool in the chat, so the upload is a real API call — no browser needed.

**The mistake worth recording:** an initial upload "succeeded" (the API returned a happy response) but had actually sent **placeholder text instead of the real file content**. The API's success response said nothing about *what bytes it stored*. This was only caught by **reading the file back from Drive after the upload and comparing it to the real report** — the round-trip verification is what surfaced the empty/placeholder content. The corrected content was then re-uploaded and re-verified. Trusting the API's 200 alone would have shipped an empty report.

### GitHub (connected, but no native tool)

The **GitHub Integration** shows "Connected" in Desktop's connector settings — but in this chat it exposes **no direct API tool**. The only way to reach GitHub from the session is **browser automation via `claude-in-chrome`** (driving the GitHub web UI), not a clean API call. That's a categorically worse integration than Drive's: slower, more brittle, and dependent on the rendered page rather than a stable API surface.

---

## Known limitations

- **Cowork requires a paid plan.** It's available on **Pro / Team / Max / Enterprise**, **not** on Free. The cross-file consistency check that caught the Privileged-Role-Administrator overclaim isn't reproducible on a Free account.
- **"Connected" ≠ "has an API tool."** The GitHub connector reports Connected in settings but exposes no direct API tool in-chat — it's only reachable through browser automation (`claude-in-chrome`). Google Drive, by contrast, offers direct API access. Don't assume a green "Connected" badge means there's a first-class tool behind it.

---

## Project structure

```
Module-9/
├── README.md
├── Incident_Response_Report_IR-2026-0719-001.docx   # formal Word IR report (~30 KB)
├── Security_Incident_Briefing.pptx                  # 8-slide executive deck (~223 KB)
├── detection-coverage-dashboard.jsx                 # interactive ATT&CK coverage (2/8 covered, 75% gap)
└── attack-timeline.jsx                              # interactive elapsed-time attack timeline
```

Source findings live in `../Module-8/complex-analysis/investigations/` (the `j.rivera` scenario) and the coverage mapping in `../Module-5/mcp-detection-kb/mappings/`.

## Lessons learned this module

- **Cross-file consistency checking catches overconfidence before it reaches a formal document.** Cowork's pass over the four Module 8 notes found a finding that had been promoted from "unconfirmed (self-escalation vs. log denormalization)" to stated fact — and because it was caught pre-finalization, both the DOCX and PPTX were corrected rather than shipping the overclaim. A single-file read would never have surfaced it; the defect only existed *between* the source note and the summary.
- **A connector's success response is not proof it stored the right bytes.** The Drive upload returned success while holding placeholder text; only reading the file *back* and comparing it to the real report exposed it. Same rule as Module 8's "verify claims against source" — extended to "verify a write by reading it back," never trust the API's own 200.
- **"Connected" connectors are not equal — native API vs. browser automation.** Google Drive gave direct API access; GitHub showed Connected but was reachable only through `claude-in-chrome` browser automation. The integration model behind a connector matters more than whether it's linked, and it's worth checking which tools actually appear before planning a workflow around one.
- **The same findings, re-formatted for the audience, are a different deliverable.** One incident produced a technical Word report (confirmed/candidate ATT&CK split, IOC appendices), a plain-language executive deck, and two interactive dashboards — each honest about the same 75% detection gap, each pitched at a different reader.
```