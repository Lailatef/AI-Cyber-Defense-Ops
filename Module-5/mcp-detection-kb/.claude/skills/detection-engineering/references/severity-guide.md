# Severity Guide

How to pick `level:` for a Sigma rule in this repo. `level:` must be exactly
one of `low`, `medium`, `high`, `critical` — no abbreviations (`crit`/`med`)
and no other values (see `SKILL.md` check 2). Every rule must also carry a
short justification for its level, in `description:` or a
`falsepositives:`-adjacent note — this guide gives the reasoning patterns to
draw that justification from.

## critical

Use when a match is close to unambiguous confirmation of a successful,
high-impact compromise, and the expected false-positive rate is near zero.

- Direct evidence of a known-malicious artifact or technique with no
  legitimate equivalent (e.g. a known attacker tool's exact command line,
  a rogue LSA authentication package matching a known Skeleton-Key pattern).
- Successful compromise of a Tier-0 asset (domain controller, CA) via a
  technique with no plausible benign explanation.

Justification pattern: "critical: <artifact/behavior> has no legitimate
equivalent and indicates <specific compromise>."

## high

Use when a match indicates likely-malicious activity with few legitimate
causes, even if not absolute proof — the kind of finding an analyst should
treat as actionable on its own, pending quick triage.

- Direct access to credential material (LSASS memory reads, NTDS.dit
  extraction, SAM/SECURITY hive dumps).
- Successful use of a high-impact lateral-movement or privilege-escalation
  technique (DCSync from a non-machine account, pass-the-hash).

Justification pattern: "high: <behavior> grants access to <sensitive
resource> with few legitimate causes beyond <known exceptions>."

See `references/example-rules/lsass_memory_access.yml` for a worked example
of a `high` rule with its justification embedded in `description:`.

## medium

Use when a match is a meaningful signal but is noisy, ambiguous, or requires
correlation with other events before it's actionable by itself — the
technique is concerning, but this specific rule's detection logic alone
produces enough false positives that an analyst needs more context.

- Volume/threshold-based detections that can be triggered by both attackers
  and misconfigured legitimate systems (e.g. high volume of RC4 TGS requests
  for Kerberoasting — also triggered by legacy service accounts).
- Behavior that is a step in an attack chain but also occurs during normal
  administration (e.g. reg.exe save of a registry hive, which admins also
  run for legitimate backup purposes).

Justification pattern: "medium: <behavior> is a meaningful signal but also
occurs during <legitimate scenario>, so treat as noisy — needs correlation
with <other signal> before escalating."

## low

Use for reconnaissance-stage or weak-signal findings: activity that's worth
recording and could contribute to a broader pattern, but on its own is
common enough (or far enough from impact) that it shouldn't page anyone.

- Enumeration/discovery techniques that are frequently run by legitimate
  tooling (vulnerability scanners, asset inventory agents).
- Single low-confidence indicators that only matter in aggregate.

Justification pattern: "low: <behavior> is common in legitimate <tooling/
scenario> and only meaningful when combined with <other indicator>."

## Choosing between adjacent levels

- If you're unsure between two levels, write the justification for each and
  pick the one whose reasoning better matches the *default* environment
  (see `detection://environment/baselines`) — not the worst-case attacker.
- A rule that needs a long list of `falsepositives:` to stay useful is a
  signal it may belong one level lower than your first instinct.
- Don't inflate severity to force attention — a `medium` rule with a clear,
  well-reasoned justification is more useful to an analyst than an
  over-triggered `high` they learn to ignore.
