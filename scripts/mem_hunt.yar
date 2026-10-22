/*
 * mem_hunt.yar - starter YARA rules for hunting malicious code in a memory dump (Day 25).
 *
 * These match generic *techniques* (shellcode prologues, an in-memory PE, reflective loading,
 * the classic injection API set, a known C2) rather than one malware family, so they work as a
 * first sweep over a raw dump or a process region. Scan with:
 *     yara -s mem_hunt.yar image.mem          # -s shows the matched bytes and their offset
 * or, inside Volatility, with windows.vadyarascan / yarascan to tie a hit to a process.
 *
 * Generic rules flag techniques that legitimate software also uses (every real PE has an MZ/PE
 * header and a DOS stub). A hit is a lead to triage - confirm which process/region it is in and
 * whether that region should hold executable code - not a verdict.
 */

rule msf_block_api_shellcode
{
    meta:
        description = "x86 'block API' shellcode prologue (cld; call; pushad; mov ebp,esp; PEB walk)"
        technique = "T1055 / shellcode"
    strings:
        $stub = { FC E8 ?? 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
    condition:
        $stub
}

rule pe_image_in_memory
{
    meta:
        description = "A PE image present in the buffer (MZ + DOS stub + PE signature) - injected if unbacked"
        technique = "T1055.012 process hollowing / T1620 reflective loading"
    strings:
        $mz  = "MZ"
        $dos = "This program cannot be run in DOS mode"
        $pe  = { 50 45 00 00 }
    condition:
        $mz and $dos and $pe
}

rule reflective_loader
{
    meta:
        description = "ReflectiveLoader export name - reflective DLL injection"
        technique = "T1620"
    strings:
        $r = "ReflectiveLoader" ascii wide
    condition:
        $r
}

rule injection_api_set
{
    meta:
        description = "The remote-injection API set resolved together in a buffer"
        technique = "T1055"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "NtUnmapViewOfSection"
        $a5 = "LoadLibraryA"
        $a6 = "GetProcAddress"
    condition:
        4 of ($a*)
}

rule c2_203_0_113_50
{
    meta:
        description = "WS-ALICE campaign C2 host (Days 21-24), ASCII or UTF-16LE"
        technique = "T1071 / IOC"
    strings:
        $ip = "203.0.113.50" ascii wide
    condition:
        $ip
}
