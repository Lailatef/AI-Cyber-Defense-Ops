# False-Positive Patterns

Concrete categories to check a new rule against before writing its
`falsepositives:` list. `SKILL.md` check 3 requires `falsepositives:` to be
present, non-empty, and list *concrete* legitimate causes — specific tools,
accounts, or jobs, not a bare placeholder. Use `"Unknown"` only as a last
resort, with reasoning for why it's genuinely unknown.

## 1. Security/monitoring tooling doing the same thing an attacker would

EDR agents, AV engines, and backup software routinely touch the same
resources credential-theft techniques target (process memory, registry
hives, SAM/NTDS files) as part of normal scanning or backup.

- Example: `rules/lsass_memory_access.yml` filters `MsMpEng.exe` (Windows
  Defender) and `WmiPrvSE.exe` out of its selection, and still documents
  "other EDR/backup agents with LSASS access exclusions not yet added" as a
  residual FP — the filter reduces noise, it doesn't eliminate the category.
- What to document: name the specific processes/products you excluded in
  the rule logic, *and* separately note that other, un-excluded tools in the
  same category remain a possible FP source.

## 2. Legitimate administrative use of a dual-use technique

Many detections key on tools or commands that are legitimate in the hands of
an administrator and malicious in the hands of an attacker — the event looks
identical either way, so the rule can't distinguish by signature alone.

- Example: `rules/t1003_002.yml` (SAM/SECURITY/SYSTEM hive dump via
  `reg.exe save`) documents "System administrators performing legitimate
  backup of registry hives" as a false positive, because `reg.exe save` is
  the same command for a backup script and for credential theft.
- What to document: the specific legitimate workflow (backup job, deployment
  script, break-glass procedure) that produces the same signature, and where
  possible, an account/host pattern that distinguishes it (see pattern 4).

## 3. Legacy or misconfigured systems that look anomalous by default

Older service accounts, legacy protocol support, or systems not yet migrated
to a hardened configuration can trigger a rule's logic under entirely benign
circumstances, because the rule is really detecting "deviation from best
practice," not "attacker present."

- Example: `rules/kerberoasting.yml` (high volume of RC4 TGS requests) would
  fire on legacy service accounts still configured to allow RC4 encryption,
  independent of any attack.
- What to document: which known legacy accounts/services in this
  environment are expected to trigger the rule (cross-reference
  `detection://environment/baselines` if one exists), so an analyst can
  triage against a known-noisy list instead of re-deriving it each time.

## 4. Expected-value baselines (known-good accounts, hosts, destinations)

Some rules are really "flag anything outside an expected set" — the FP
pattern is any legitimate member of that set that hasn't been enumerated
yet, or a new legitimate member added after the rule was written.

- Example: `rules/dcsync.yml` (AD replication request from a non-machine
  account) has expected DCSync source accounts (`DC01$`/`DC02$` machine
  accounts and the `BACKUP-SVC` service account) documented in the
  `dcsync_replication_accounts` baseline in `environment/baselines.yml`; the
  rule's FP scenario is exactly "a legitimate account in that baseline that
  isn't reflected in the rule's exclusion list yet."
- Example: `rules/t1187.yml` (forced-authentication/PetitPotam-style
  coercion) has an analogous `outbound_smb_destinations` baseline covering
  expected outbound SMB destinations (RFC1918 ranges plus one approved
  Azure Files endpoint).
- What to document: point to the baseline resource by name, and note that
  the baseline can drift — new legitimate accounts/hosts added to the
  environment are a recurring FP source until the baseline is updated.

## 5. Volume/threshold detections tripped by legitimate bursts

Any rule built on "N events in a time window" (brute-force lockouts,
Kerberoasting request volume) will also fire on legitimate bursts: a
misconfigured client retrying a bad password, a load test, a batch job that
authenticates many accounts in quick succession.

- Example: `rules/brute_force.yml` (high volume of 4625 failed logons) is
  documented as closed false-positive in `investigations/INV-2026-004.yml`
  — a WEB01 failed-logon spike matching a `known_noisy_sources` baseline
  entry, not an actual brute-force attempt.
- What to document: the specific known-noisy source (a public-facing host,
  a scheduled job, a misconfigured service) and, if one exists, a link to a
  past investigation that confirmed the pattern as benign — this saves the
  next analyst from re-investigating the same closed case.

## Checklist when writing `falsepositives:` for a new rule

1. Does the technique overlap with something security/monitoring tooling
   does normally? (pattern 1)
2. Is the underlying command/API dual-use, with a legitimate admin workflow
   that looks identical? (pattern 2)
3. Could a legacy/misconfigured-but-benign system trigger this by default?
   (pattern 3)
4. Is there an expected-value baseline this rule should be checked against
   (`detection://environment/baselines`)? (pattern 4)
5. Is the detection logic volume/threshold-based, and if so, what legitimate
   burst could hit that threshold? (pattern 5)
6. Have any of these FP categories already produced a documented
   investigation (`detection://investigations`)? Link it instead of
   re-describing it.

If none of the six apply and you're still writing `"Unknown"`, say why in
the same line (e.g. `"Unknown — no environment-specific baseline exists yet
for this data source"`), not as a bare placeholder.
