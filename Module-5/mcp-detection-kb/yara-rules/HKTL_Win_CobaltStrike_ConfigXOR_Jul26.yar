// Targets a Cobalt Strike Beacon's XOR-encoded configuration blob rather
// than plaintext strings, so it survives Beacon's default
// stage.obfuscate string obfuscation for versions that still use a fixed
// single-byte XOR key. Two indicators, both publicly documented:
//   - "sprng\x00" -- an internal Beacon string that survives config
//     encoding (JPCERT CobaltStrikeScan indicator)
//   - long runs of a single repeated byte where the config's null-byte
//     padding decodes to that byte under a single-byte XOR key -- 0x69
//     was Beacon 3.x's default key, 0x2e a common Beacon 4.x default
//
// Known limitation: Cobalt Strike 4.8+ moved stage.obfuscate to a
// randomly generated MULTI-byte XOR key by default, which this rule does
// NOT catch (no fixed repeated-byte run to key on). This targets older/
// default-configured beacons specifically, not obfuscated 4.8+ builds.
// Companion to HKTL_Win_CobaltStrike_BeaconStrings_Jul26.yar, which
// catches unobfuscated beacons via plaintext strings instead.
//
// Accepted performance trade-off (flagged by atom_analyzer.py, not
// silently ignored): $xor69_run and $xor2e_run each score 10/100 for atom
// quality -- a run of one repeated byte has no diverse 4-byte window, so
// YARA-X falls back to slower verification wherever that byte repeats.
// This is structural, not a mistake: the indicator IS "the config's
// XOR-encoded null padding," which is low-entropy by definition. JPCERT's
// original published cobaltstrikescan YARA rule uses this identical
// 8-byte-repeat pattern in production. Mitigated here by the filesize/MZ
// prefilter and by requiring $sprng (a good-atom string) alongside it, so
// the poor atom is never the sole gate. If deploying at scale across a
// large corpus, re-benchmark before treating this as a solved trade-off.
//
// Validated: yara_x.Compiler().build() compiles clean; yara_lint.py 0
// issues; atom_analyzer.py flags both XOR-run strings as noted above
// ($sprng itself scores well); functional yara_x.Scanner test against
// synthetic bytes, 6/6 as expected (matches sprng+0x69 and sprng+0x2e,
// does not match sprng-only, XOR-run-only, missing MZ magic bytes, or the
// same true-positive content padded past the 300KB filesize cap).
// NOT yet tested against a real Cobalt Strike beacon DLL or a goodware
// corpus -- validate against both before production deployment.
rule HKTL_Win_CobaltStrike_ConfigXOR_Jul26
{
    meta:
        description = "Detects a Cobalt Strike Beacon's single-byte-XOR-encoded configuration blob via its characteristic internal 'sprng' string plus a repeated-byte run from the config's XOR-encoded null padding (XOR key 0x69 or 0x2e)"
        author = "Detection Engineering Team"
        reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
        date = "2026-07-16"
        attack_technique = "S0154"

    strings:
        $sprng = { 73 70 72 6E 67 00 }             // "sprng\x00"
        $xor69_run = { 69 69 69 69 69 69 69 69 }   // 8x 0x69 (Beacon 3.x default XOR key)
        $xor2e_run = { 2E 2E 2E 2E 2E 2E 2E 2E }   // 8x 0x2e (Beacon 4.x default XOR key)

    condition:
        filesize < 300KB and
        uint16(0) == 0x5A4D and
        $sprng and
        1 of ($xor69_run, $xor2e_run)
}
