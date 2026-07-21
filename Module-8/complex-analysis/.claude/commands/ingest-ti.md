---
description: Ingest a threat intelligence report URL and extract TTPs, IOCs, and a simulation plan
argument-hint: <url>
---

# Threat Intelligence Ingestion

Ingest the threat intel report at `$1` and produce a structured analysis.

If `$1` is empty, stop and ask the user for a report URL.

## Step 1: Extract Content

Run `defuddle` to get clean markdown content from the URL:

```bash
defuddle parse "$1" --markdown
```

## Step 2: Analyze the Content

With the extracted content, identify:

### Threat Overview
- Campaign/threat actor name (if mentioned)
- Target industries/regions
- Time period of activity

### TTPs (Tactics, Techniques, Procedures)
Map observed behaviors to MITRE ATT&CK:
- Initial Access techniques
- Execution techniques
- Persistence techniques
- Privilege Escalation techniques
- Defense Evasion techniques
- Credential Access techniques
- Discovery techniques
- Lateral Movement techniques
- Collection techniques
- Command and Control techniques
- Exfiltration techniques
- Impact techniques

For each technique:
- ATT&CK ID (e.g., T1566.001)
- How it was used in this campaign
- Confidence level (high/medium/low based on detail in report)

### Indicators of Compromise
Extract any IOCs mentioned:
- IP addresses
- Domains
- File hashes
- File paths
- Registry keys
- Email addresses

### Simulation Plan
Based on the TTPs identified, suggest Atomic Red Team tests:
- List applicable atomic tests by technique ID
- Note any techniques that don't have atomic tests
- Prioritize by: techniques with high confidence + available atomic tests

## Step 3: Output

Create a structured markdown file in `analysis/` with:
- Filename: `analysis/ti-<date>-<campaign-name>.md`
- Frontmatter with source URL and extraction date
- All sections above
- Links to ATT&CK technique pages
