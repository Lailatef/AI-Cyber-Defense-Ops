// Targets an unmodified/default Cobalt Strike Beacon DLL via internal
// printf-style format strings used by its built-in service-exec ("psexec")
// and file-copy ("jump") lateral-movement features. These exact format
// strings, in this exact combination, are not typical of legitimate
// software -- documented publicly by Elastic
// (HKTL_CobaltStrike_Beacon_Strings, see reference below).
//
// Scope: written for scanning dropped/on-disk beacon DLL files (adds an
// MZ-header + filesize prefilter for performance per this skill's
// short-circuit guidance). Elastic's original rule targets live memory
// regions and omits that prefilter, since a reflectively-loaded beacon's
// scanned memory page may not start at the module's PE header -- drop the
// uint16(0)==0x5A4D check if adapting this for memory/process scanning.
//
// Known limitation: only matches an UNOBFUSCATED beacon. Cobalt Strike's
// stage.obfuscate option (single-byte XOR pre-4.8, randomized multi-byte
// XOR from 4.8+) will hide these strings entirely -- see the companion
// rule HKTL_Win_CobaltStrike_ConfigXOR_Jul26.yar, which targets the
// encoded config blob instead and survives basic string obfuscation.
//
// yara_lint.py note: flags $fmt2/$fmt3 with FP-prone-substring warnings
// (W005) because they contain "%s"/"%d". That check does a naive
// substring match; the actual strings are long, highly specific compound
// format strings ("Started service %s on %s", "%s as %s\%s: %d"), not
// bare format specifiers -- warnings, not errors, left as-is.
//
// Validated: yara_x.Compiler().build() compiles clean; yara_lint.py 0
// errors (3 W005 warnings noted above); atom_analyzer.py all 3 strings
// good atom quality; functional yara_x.Scanner test against synthetic
// bytes, 5/5 as expected (matches on 2-of-3 combinations, does not match
// on 1-of-3, no fmt strings, or fmt strings without the MZ magic bytes).
// NOT yet tested against a real Cobalt Strike beacon DLL or a goodware
// corpus -- validate against both before production deployment.
rule HKTL_Win_CobaltStrike_BeaconStrings_Jul26
{
    meta:
        description = "Detects an unobfuscated Cobalt Strike Beacon DLL via characteristic internal format strings from its service-exec and file-copy lateral-movement routines"
        author = "Detection Engineering Team"
        reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
        date = "2026-07-16"
        attack_technique = "S0154"

    strings:
        $fmt1 = "%02d/%02d/%02d %02d:%02d:%02d"
        $fmt2 = "Started service %s on %s"
        $fmt3 = "%s as %s\\%s: %d"

    condition:
        filesize < 10MB and
        uint16(0) == 0x5A4D and
        2 of ($fmt*)
}
