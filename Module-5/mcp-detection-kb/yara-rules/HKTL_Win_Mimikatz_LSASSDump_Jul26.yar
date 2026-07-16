// DRAFT: strings verified against publicly documented Mimikatz source/build
// strings (gentilkiwi/mimikatz on GitHub). Complements this repo's Sigma
// rule rules/lsass_memory_access.yml (T1003.001), which detects the
// *access* event via ETW; this rule detects the *tool artifact* on disk.
//
// Validated:
//   - yara_x.Compiler().build() compiles clean (equivalent to `yr check`
//     passing -- same underlying Rust engine, no yr CLI installed here)
//   - yara_lint.py: 0 issues
//   - atom_analyzer.py: all strings good atom quality
//   - Functional scan test (yara_x.Scanner, synthetic bytes, all 4/4 as
//     expected): matches a fake MZ file containing the wide-encoded
//     "sekurlsa::logonpasswords" string; does NOT match plain unrelated
//     text, an ASCII (non-wide) copy of the same string, or the wide
//     string in a non-MZ file
// NOT yet tested against: a real mimikatz.exe binary, or a goodware corpus
// of real PE files -- validate against both before production deployment.
rule HKTL_Win_Mimikatz_LSASSDump_Jul26
{
    meta:
        description = "Detects Mimikatz, a public credential-dumping hacktool that extracts plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS process memory (MITRE ATT&CK T1003.001)"
        author = "Detection Engineering Team"
        reference = "https://github.com/gentilkiwi/mimikatz"
        date = "2026-07-16"
        attack_technique = "T1003.001"

    strings:
        $cmd1 = "sekurlsa::logonpasswords" wide
        $cmd2 = "sekurlsa::pth" wide
        $cmd3 = "sekurlsa::minidump" wide
        $author = "gentilkiwi" ascii
        $pdb = "mimikatz.pdb" ascii

    condition:
        filesize < 5MB and
        uint16(0) == 0x5A4D and
        any of them
}
