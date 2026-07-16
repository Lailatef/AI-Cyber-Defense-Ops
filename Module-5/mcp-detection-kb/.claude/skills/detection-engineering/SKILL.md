---
name: detection-engineering
description: |
  Detection rule development standards. Activate when:
  - Writing, creating, or modifying a detection rule (Sigma or otherwise)
  - Reviewing detection rules for quality or completeness
  - Discussing detection coverage, gaps, or improvements
  - Working with YAML files containing detection logic
  - Asked to validate, check, or audit detection rules
  - Asked which ATT&CK technique(s) a detection maps to
---

# Detection Engineering Standards

Apply these standards whenever you are writing, editing, or reviewing a Sigma
detection rule, discussing detection coverage/gaps, or otherwise working with
YAML files under `rules/` (or any new curated detection rule).

Use this skill when:
- Writing, creating, or modifying a detection rule (Sigma or otherwise)
- Reviewing an existing detection rule (this repo's curated rules or a rule a
  user pastes in)
- Discussing detection coverage (gaps, `analyze_coverage`, `suggest_rule`)
- Reading, editing, or generating YAML detection files
- Asked to validate, check, or audit detection rules
- Asked which ATT&CK technique(s) a detection maps to

## Required checks

Before treating a Sigma rule as done, verify all five:

1. **ATT&CK mapping** — the rule's `tags:` list includes at least one
   technique in `attack.tXXXX` format (lowercase, e.g. `attack.t1003.006`).
   A rule with no `attack.tXXXX` tag is not mapped — flag it.

2. **Severity is justified** — `level:` is exactly one of `low`, `medium`,
   `high`, `critical` (no other values, no abbreviations like `crit`/`med`).
   The rule must also carry a short justification for that severity —
   either in the `description:` field or a `falsepositives:`-adjacent note —
   explaining *why* this level (e.g. "high: direct credential material
   access with few legitimate causes" vs. "medium: noisy signal, needs
   correlation"). A bare `level:` with no reasoning anywhere in the rule is
   a gap.

3. **False positives documented** — `falsepositives:` is present and
   non-empty, listing concrete legitimate causes (specific tools, accounts,
   scheduled jobs, or "Unknown" only as a last resort with reasoning, not as
   a default placeholder).

4. **At least one test case** — the rule must be paired with a way to prove
   it fires: either a reference to a sample EVTX/log file it has been (or
   should be) run against, or an inline example event, or a note in this
   repo's `rules/` breakdown of tested/untested status. A rule with no way
   to verify it ever matches real data is incomplete — say so explicitly
   rather than assuming it works.

5. **Naming convention** — rule identifiers/filenames are lowercase with
   underscores (e.g. `lsass_memory_access`, `t1003_002_registry_access`),
   matching the existing `rules/` directory. Reject `CamelCase`,
   `kebab-case`, or spaces in rule names/filenames.

## How to apply

- **When writing a new rule**: draft it, then self-check against all five
  items above before presenting it as finished. Don't silently skip a
  missing item — call it out and either fix it or ask.
- **When reviewing a rule** (this repo's or user-provided): go through the
  five checks explicitly and report pass/fail per item, not just a vague
  "looks good."
- **When discussing coverage** (e.g. via `analyze_coverage`/`suggest_rule`):
  note that a technique being "covered" only counts if the covering rule
  meets these five standards — a rule that exists but fails, say, the
  false-positive or test-case check is weaker coverage than it looks.
- Per this repo's `CLAUDE.md`: a rule's `status:` field (`stable`/`test`/
  `experimental`) is a maturity label, not proof of testing. Don't conflate
  "has a `status:` field" with satisfying the test-case requirement above —
  only `t1187.yml` is documented as empirically validated against a real
  EVTX sample; treat other rules' test coverage claims accordingly.

## Validation

After creating or modifying a rule, validate it:

```
python .claude/skills/detection-engineering/scripts/validate-rule.py path/to/rule.yml
```

This checks the ATT&CK mapping, severity, false-positives, and test-case
requirements above and returns a JSON report (`valid`, per-check detail, and
an `issues` list). A non-zero exit code means at least one check failed —
treat that the same as failing the manual self-check, not as advisory only.
Note: on this repo's Windows setup, `python` may resolve to a non-functional
Microsoft Store stub — use `py` instead if `python` fails.

## References

Supporting material under `references/`:

- `references/example-rules/lsass_memory_access.yml` — a fully worked
  example rule that passes all five required checks above (including a
  `# test-case:` comment and an in-line severity justification), to copy
  the shape from when authoring a new rule.
- `references/severity-guide.md` — criteria and justification patterns for
  choosing `low`/`medium`/`high`/`critical`.
- `references/false-positive-patterns.md` — recurring false-positive
  categories (security-tooling overlap, dual-use admin commands, legacy
  systems, baseline drift, volume-threshold bursts) with a checklist for
  writing `falsepositives:` on a new rule.
