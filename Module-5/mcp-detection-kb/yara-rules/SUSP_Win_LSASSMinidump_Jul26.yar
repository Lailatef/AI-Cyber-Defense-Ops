// DRAFT: magic bytes and module-string layout verified against the public
// MINIDUMP_HEADER / MINIDUMP_MODULE format documentation.
//
// Validated:
//   - yara_x.Compiler().build() compiles clean (equivalent to `yr check`
//     passing -- same underlying Rust engine, no yr CLI installed here)
//   - yara_lint.py: 0 issues
//   - atom_analyzer.py: all strings good atom quality
//   - Functional scan test (yara_x.Scanner, synthetic bytes, all 4/4 as
//     expected): matches a fake MDMP file containing wide-encoded
//     "lsass.exe" plus either "lsasrv.dll" or "wdigest.dll"; does NOT
//     match a same-shape dump of an unrelated process (notepad.exe), or
//     the right strings without the MDMP magic bytes
// NOT yet tested against: a real captured lsass.dmp, or a goodware corpus
// of real (non-LSASS) process minidumps -- validate against both before
// production deployment.
//
// Tool-agnostic: catches the *artifact* (a minidump of lsass.exe), not any
// one tool's signature, so it complements
// yara-rules/HKTL_Win_Mimikatz_LSASSDump_Jul26.yar (which only fires on
// Mimikatz itself) and this repo's Sigma rule rules/lsass_memory_access.yml
// (which detects the *access* event via ETW, not the resulting file).
// Covers Mimikatz's offline `sekurlsa::minidump`, ProcDump
// (`procdump -ma lsass.exe`), the comsvcs.dll MiniDump LOLBin technique
// (`rundll32 comsvcs.dll,MiniDump <pid> lsass.dmp full`), and manual
// Task Manager "Create dump file" -- all of which produce this same
// artifact shape.
//
// Known false-positive sources: legitimate crash-dump collection if
// lsass.exe itself crashes (Windows Error Reporting), or authorized
// incident-response/support use of ProcDump/Task Manager under change
// control. Triage by confirming who/what created the file and whether it
// was expected.
rule SUSP_Win_LSASSMinidump_Jul26
{
    meta:
        description = "Detects a Windows minidump file (.dmp) of the LSASS process, the artifact left behind by any LSASS-dumping technique (Mimikatz, ProcDump, comsvcs.dll MiniDump, Task Manager) regardless of which tool produced it (MITRE ATT&CK T1003.001)"
        author = "Detection Engineering Team"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        date = "2026-07-16"
        attack_technique = "T1003.001"

    strings:
        $proc_lsass = "lsass.exe" wide
        $mod_lsasrv = "lsasrv.dll" wide
        $mod_wdigest = "wdigest.dll" wide

    condition:
        filesize < 200MB and
        uint32(0) == 0x504D444D and
        $proc_lsass and
        1 of ($mod_lsasrv, $mod_wdigest)
}
